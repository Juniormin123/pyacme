import base64
import logging
import socketserver
import hashlib
import json
import sys
import time
from argparse import Namespace
from http.server import SimpleHTTPRequestHandler
from typing import Any, Dict, List, Union
from pathlib import Path
from zipfile import ZipFile

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.x509 import NameAttribute, DNSName, SubjectAlternativeName
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec
import requests

from pyacme.base import _JWKBase
from pyacme.jwk import JWKRSA, JWKES256
from pyacme.settings import *


# only handle log record with level DEBUG
debug_hd = logging.StreamHandler(stream=sys.stdout)
debug_hd.setFormatter(logging.Formatter(LOG_DEBUG_FMT, style='{'))
debug_hd.setLevel(logging.DEBUG)
debug_hd.addFilter(lambda r: r.levelno == logging.DEBUG)

# handle log level INFO and above
info_hd = logging.StreamHandler(stream=sys.stdout)
info_hd.setFormatter(logging.Formatter(LOG_FMT, style='{'))
info_hd.setLevel(LOG_LEVEL)

base_logger = logging.getLogger('pyacme')
base_logger.addHandler(debug_hd)
base_logger.addHandler(info_hd)
base_logger.setLevel(LOG_LEVEL)

logger = logging.getLogger(__name__)
info = logger.info


# test logging
# def info_test(msg): info(msg)
# def debug_test(msg): logger.debug(msg)


def get_keyAuthorization(token: str, jwk: _JWKBase) -> str:
    """
    construct auth string by joining challenge token and key thumbprint.

    see https://tools.ietf.org/html/rfc8555#section-8.1
    """
    # see https://github.com/diafygi/acme-tiny/blob/master/acme_tiny.py#L86
    # sort keys required by https://tools.ietf.org/html/rfc7638#section-4
    s_jwk = json.dumps(jwk._container, sort_keys=True, separators=(',', ':'))
    jwk_hash = hashlib.sha256(s_jwk.encode(encoding='utf-8')).digest()
    b64 = base64.urlsafe_b64encode(jwk_hash).strip(b'=')
    return f"{token}.{str(b64, encoding='utf-8')}"


def get_dns_chall_txt_record(token: str, jwk: _JWKBase) -> str:
    """
    return a string of a dns TXT record; the whole dns record looks like
    `_acme-challenge.www.example.org. 300 IN TXT keyauth_digest`

    see https://tools.ietf.org/html/rfc8555#section-8.4
    """
    keyauth = get_keyAuthorization(token, jwk)
    # sha256 on the keyauth string, see rfc8555 8.4 p66
    keyauth_digest = hashlib.sha256(keyauth.encode('utf-8')).digest()
    b64 = base64.urlsafe_b64encode(keyauth_digest).strip(b'=')
    return str(b64, encoding='utf-8')


def generate_rsa_privkey(privkey_dir: str, 
                         keysize = 2048,
                         key_name = 'certkey.key') -> rsa.RSAPrivateKey:
    """
    generate private key to specified dir using `cryptography` package
    """
    # create a private key if not given
    csr_priv_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=keysize,
        backend=default_backend()
    )
    csr_priv_key_b = csr_priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(f'{privkey_dir}/{key_name}', 'wb') as f:
        f.write(csr_priv_key_b)
    return csr_priv_key


def generate_ecdsa_privkey(privkey_dir: str, 
                           curve = ec.SECP256R1(),
                           key_name = 'certkey.key'
                           ) -> ec.EllipticCurvePrivateKey:
    """
    generate ecdsa key with SECP256R1 to specified dir
    """
    # create a private key if not given
    csr_priv_key = ec.generate_private_key(
        curve=curve,
        backend=default_backend()
    )
    csr_priv_key_b = csr_priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(f'{privkey_dir}/{key_name}', 'wb') as f:
        f.write(csr_priv_key_b)
    return csr_priv_key


def generate_privkey(key_type: str,
                     privkey_dir: str, 
                     key_name = 'certkey.key',
                     key_size = 2048
                     ) -> Union[ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey]:
    if key_type not in set(CSR_SUPPORTED_KEY_TYPE+KEY_ACCT_KEYTYPE):
        raise ValueError(f'not supported privated key type {key_type}')
    if key_type == 'rsa':
        return generate_rsa_privkey(privkey_dir, key_size, key_name)
    elif key_type == 'es256':
        return generate_ecdsa_privkey(privkey_dir, ec.SECP256R1, key_name)
    else:
        raise NotImplementedError(f'key_type {key_type} not implemented')
    # other keytype


def create_csr(privkey: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey],
               domains: List[str],
               *, 
               C = '', 
               ST = '', 
               L = '', 
               O = '', 
               OU = '', 
               emailAddress = '') -> bytes:
    """
    generate csr using `cryptography.x509`;
    """
    csr = x509.CertificateSigningRequestBuilder()
    cn = domains[0]
    csr = csr.subject_name(
        x509.Name(
            [
                NameAttribute(NameOID.COUNTRY_NAME, C),
                NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, ST),
                NameAttribute(NameOID.LOCALITY_NAME, L),
                NameAttribute(NameOID.ORGANIZATION_NAME, O),
                NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, OU),
                NameAttribute(NameOID.COMMON_NAME, cn),
                NameAttribute(NameOID.EMAIL_ADDRESS, emailAddress),
            ]
        )
    )
    alt_names = tuple(DNSName(d) for d in domains)
    csr = csr.add_extension(SubjectAlternativeName(alt_names), critical=False)
    csr_signed = csr.sign(
        privkey, algorithm=hashes.SHA256(), backend=default_backend()
    )
    return csr_signed.public_bytes(serialization.Encoding.DER)


def parse_csr(privkey: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey], 
              domains: List[str], 
            #   extra: List[str] = [], 
            #   engine: str = 'openssl',
              **subjects: str) -> bytes:
    """
    ouput DER format bytes of a CSR, subjects for csr list below:
     * C = Country two-digit, like GB or US;
     * ST = State or Province
     * L  = Locality
     * O  = Organization Name        
     * OU = Organizational Unit Name
     * emailAddress = test@email.address

    """
    return create_csr(privkey, domains, **subjects)


def save_cert(cert_resp: requests.Response, cert_dir: str) -> requests.Response:
    """
    return 3 cert files 
    as below
     * `cert.pem` the server cert file;
     * `chain.pem` intermediate cert file;
     * `fullchain.pem` both the cert and intermediate, as reponse by the ACME
     server
    """
    fullchain = cert_resp.text
    fullchain_path = Path(cert_dir).absolute() / 'fullchain.pem'
    with open(f'{fullchain_path!s}', 'w') as f:
        f.write(fullchain)
    
    cert, chain = fullchain.split('-----END CERTIFICATE-----\n', maxsplit=1)
    cert += '-----END CERTIFICATE-----\n' 

    cert_path = Path(cert_dir).absolute() / 'cert.pem'
    with open(f'{cert_path!s}', 'w') as f:
        f.write(cert)
    
    chain_path = Path(cert_dir).absolute() / 'chain.pem'
    with open(f'{chain_path!s}', 'w') as f:
        f.write(chain)

    return cert_resp


def run_http_server(path: Union[Path, str], port = 80) -> None:
    """run a pyhton http server on port 80 to reponse acme challenge"""
    class Handler(SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs) :
            super().__init__(*args, directory=str(path), **kwargs)

    with socketserver.TCPServer(
        ('', port), Handler, bind_and_activate=False) as httpd:

        # TODO proper exit for http server

        # prevent "OSError: [Errno 98] Address already in use" when testing
        httpd.allow_reuse_address = True
        httpd.server_bind()
        httpd.server_activate()
        info(f'serving at port {port}')
        httpd.serve_forever()


def jwk_factory(acct_priv_key_path: str) -> _JWKBase:
    """generate jwk object according private key file"""
    with open(acct_priv_key_path, 'rb') as f:
        acct_priv = serialization.load_pem_private_key(
            data=f.read(),
            password=None,
            backend=default_backend()
        )
        if isinstance(acct_priv, rsa.RSAPrivateKey):
            jwk = JWKRSA(
                priv_key=acct_priv,
                n=acct_priv.public_key().public_numbers().n,
                e=acct_priv.public_key().public_numbers().e
            )
        elif isinstance(acct_priv, ec.EllipticCurvePrivateKey):
            if isinstance(acct_priv.curve, ec.SECP256R1):
                jwk = JWKES256(acct_priv)
            else:
                raise NotImplementedError(
                    f'ecdsa curve {acct_priv.curve} not implemented'
                )
        else:
            raise TypeError(f'key type {type(acct_priv)} not supported')
        return jwk


def backup_certs(cert_path: str, backup_path: str) -> None:
    if not list(Path(cert_path).iterdir()):
        # print('no backup performed')
        info('no backup performed')
        return
    date_time = time.strftime(BAK_TIME_FMT, time.localtime())
    bak_zip_name = BAK_DEFAULT_PATTERN.format(date_time=date_time)
    with ZipFile(Path(backup_path)/bak_zip_name, 'w') as zip_f:
        for f in Path(cert_path).iterdir():
            zip_f.write(str(f))
    info(f'certificates backup zipped to {Path(backup_path)/bak_zip_name}')


def domains_check(domains: List[str]) -> List[str]:
    """
    all input domains should have the same primary, 
    e.g.
     * `example.com`, `a.example.com` are valid
     * `example.com`, `a.example1.com` are invalid
     * `domains=["a.x.com", "b.x.com"]` will be converted to 
     `["x.com", "a.x.com", "b.x.com"]`
    if top-level like `example.com` is not given in `domains`, it will be 
    added here
    """
    if len(domains) == 1:
        return domains
    primary_set: List[str] = []
    for d in domains:
        primary = '.'.join(d.split('.')[-2:])
        primary_set.append(primary)
    if len(set(primary_set)) == 1:
        primary = primary_set.pop()
        # if top-level given by user but not in the first
        if primary in domains:
            # move primary to the first element in domains list
            domains_mod = sorted(domains, key=len)
            return domains_mod
        else:
            # if top-level is not given by user, add it to domains
            return [primary] + domains
    else:
        raise ValueError(f'input domains {domains} have different top-level')


def check_path(wd: str, domains: List[str]) -> str:
    """
    for default file structure, `root="~/.pyacme"`; may be subsitituted by user
    given value.
    ```
    {root}/{domain_name}
    +-- acct
    |   +-- acct.pem
    +-- chall_http
    |   +-- {http_chall_token}
    |   +-- ...
    +-- cert
    |   +-- cert.key
    |   +-- chain.pem
    |   +-- fullchain.pem
    +-- backup
    |   +-- bak_{date_time}.zip
    |   +-- ...
    ```
    multiple domains will be concatenated and placed under one directory
    """
    d = '_'.join(domains)
    wd_path = Path(wd).expanduser().absolute() / d
    if not wd_path.exists():
        wd_path.mkdir(parents=True, exist_ok=True)
        (wd_path / WD_ACCT).mkdir()
        (wd_path / WD_HTTP01).mkdir()
        (wd_path / WD_CERT).mkdir()
        (wd_path / WD_BAK).mkdir()
        acme_http = Path('.well-known/acme-challenge')
        (wd_path / WD_HTTP01 / acme_http).mkdir(parents=True)
        info(f'workding directory {wd_path!s} created')
    else:
        info(f'workding directory {wd_path!s} exists')
    return d


def create_new_acct_key(key_path: Path, acct_key_type: str) -> None:
    # passed in key_path is a file location
    if not key_path.exists():
        key_path = key_path.parent
        generate_privkey(acct_key_type, str(key_path), KEY_ACCT)
        info(f'new {acct_key_type} account private key generated at {key_path}')
    else:
        info(f'use existed account private key at {key_path}')


def main_param_parser(args: Namespace) -> dict:
    """
    parse params passed to `main()`, assign proper default value if needed;
    perform `check_path()` at the end of this parser;
    arg `--debug` is not included here
    """
    # set logging level
    if args.debug:
        logging.getLogger('pyacme').setLevel(logging.DEBUG)

    domains = domains_check(args.domain)

    # use original given domains for path creation
    joined_domain = check_path(args.working_directory, args.domain)

    param_dict: Dict[str, Any] = dict()

    # wildcard domain only available for dns mode
    param_dict['domains'] = domains
    for d in args.domain:
        if '*' in d:
            param_dict['mode'] = 'dns'
            break
    else:
        param_dict['mode'] = args.mode
    
    # create new acct key if not exist in working dir
    wd = Path(args.working_directory).expanduser().absolute() / joined_domain
    if not args.account_private_key:
        key_path = Path(wd) / WD_ACCT / KEY_ACCT
        create_new_acct_key(key_path, args.acct_key_type)
        param_dict['acct_priv_key'] = str(key_path)
    else:
        param_dict['acct_priv_key'] = args.account_private_key
        info(f'use user given account key at {args.account_private_key}')

    # parse param for cert_path and chall_path
    param_dict['cert_path'] = str(wd / WD_CERT)
    param_dict['chall_path'] = str(wd / WD_HTTP01)
            
    # parse subject names string for CSR, append country code to csr_dict
    csr_dict = {'C': args.country_code}
    if args.csr_subjects:
        csr_list = args.csr_subjects.split(',')
        csr_dict.update({i[0]:i[1] for i in [j.split('=') for j in csr_list]})
    param_dict['subject_names'] = csr_dict

    # parse dns specifics
    dns_dict = dict()
    if args.dns_specifics:
        dns_list = args.dns_specifics.split(',')
        dns_dict = {i[0]:i[1] for i in [j.split('=') for j in dns_list]}
    param_dict['dns_specifics'] = dns_dict

    # direct pass params
    key_list = [
        'contact',
        'not_before',
        'not_after',
        'dnsprovider',
        'access_key',
        'secret',
        'CA_entry',
        'poll_interval',
        'poll_retry_count',
        'csr_priv_key_type',
        'csr_priv_key_size',
        'chall_resp_server_port', 
        'no_ssl_verify'
    ]
    for key in key_list:
        param_dict[key] = getattr(args, key)
    
    # backup old cert files if exist
    backup_certs(str(wd/WD_CERT), str(wd/WD_BAK))

    return param_dict