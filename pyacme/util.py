import base64

import socketserver
import subprocess
import hashlib
import json
from argparse import Namespace
from http.server import SimpleHTTPRequestHandler
from typing import List, Union
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.x509 import NameAttribute, DNSName, SubjectAlternativeName
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
import requests

from pyacme.base import _JWKBase
from pyacme.jwk import JWKRSA
from pyacme.settings import *


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
    # TODO proper way to store generated csr private key
    csr_priv_key_b = csr_priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(f'{privkey_dir}/{key_name}', 'wb') as f:
        f.write(csr_priv_key_b)
    return csr_priv_key


def create_csr(privkey: rsa.RSAPrivateKey,
               domains: List[str],
               *, 
               C = '', 
               ST = '', 
               L = '', 
               O = '', 
               OU = '', 
               emailAddress = '') -> bytes:
    """
    generate csr using `cryptography.x509`
    """
    csr = x509.CertificateSigningRequestBuilder()
    # cn = ','.join([f'DNS:{d}' for d in domains])
    cn = ','.join(domains)
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
    # return csr_signed
    return csr_signed.public_bytes(serialization.Encoding.DER)


def create_csr_openssl(privkey_path: str, 
                       domains: List[str], 
                       extra: List[str] = [], 
                       **subjects: str) -> bytes:
    """
    generate csr using `openssl req`, 
    `domains` will be added to csr using `-addtext` option of openssl.
    """
    if subjects:
        names = '/' + '/'.join([f'{k}={v}' for k, v in subjects.items()])
    else:
        names = ''
    altnames = 'subjectAltName=' + ','.join([f'DNS:{d}' for d in domains])
    # TODO figure out how to add CN with multiple domains
    subj = f'/CN={",".join(domains)}' + names
    # private key that is different from the account private key should be used

    output_p = subprocess.run(
        [
            'openssl', 'req', '-new', 
            # '-key', privkey_path,
            '-key', privkey_path,
            '-outform', 'DER', 
            '-subj', subj,
            '-addext', altnames,
            *extra
        ],
        capture_output=True,
        check=True
    )
    output_b = output_p.stdout
    return output_b


def parse_csr(privkey: Union[rsa.RSAPrivateKey, str], 
              domains: List[str], 
              extra: List[str] = [], 
              engine: str = 'openssl',
              **subjects: str) -> bytes:
    """
    ouput DER format bytes of a CSR, `C` is required for `engine="cryptography"`
    subjects for csr list below:
     * C = Country two-digit, like GB or US;
     * ST = State or Province
     * L  = Locality
     * O  = Organization Name        
     * OU = Organizational Unit Name
     * emailAddress = test@email.address

    """
    if engine == 'cryptography' and isinstance(privkey, rsa.RSAPrivateKey):
        return create_csr(privkey, domains, **subjects)
    elif engine == 'openssl' and isinstance(privkey, str):
        return create_csr_openssl(privkey, domains, extra, **subjects)
    else:
        raise ValueError(
            f'unrecognized csr parser args "{engine=}" and "{privkey=}"'
        )

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

    with socketserver.TCPServer(('', port), Handler) as httpd:
        try:
            # TODO proper log
            print(f'serving at port {port}')
            httpd.serve_forever()
        except KeyboardInterrupt:
            httpd.server_close()


def jwk_factory(acct_priv_key: str) -> _JWKBase:
    """generate jwk object according private key file"""
    with open(acct_priv_key, 'rb') as f:
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
        # elif isinstance(acct_priv, ec.EllipticCurvePrivateKey):
        #     # TODO 
        #     pass
        else:
            raise TypeError(f'key type {type(acct_priv)} not supported')
        return jwk


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
        print(f'workding directory {wd_path!s} created')
    else:
        print(f'workding directory {wd_path!s} exists')
    return d


def main_param_parser(args: Namespace) -> dict:
    """parse params passed to `main()`, assign proper default value if needed"""

    # TODO first check if input domains are valid

    # TODO only support 2 domains at most for now
    if len(args.domain) > 2:
        raise ValueError('domain count more than 2 is not supported yet')

    joined_domain = check_path(args.working_directory, args.domain)

    param_dict = dict()

    # wildcard domain only available for dns mode
    param_dict['domains'] = args.domain
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
        if not key_path.exists():
            generate_rsa_privkey(
                str(key_path.parent), 
                keysize=KEY_SIZE, 
                key_name=KEY_ACCT
            )
            print(f'new account private key generated at {key_path}')
        else:
            print(f'use existed account private key at {key_path}')
        param_dict['acct_priv_key'] = str(key_path)
    else:
        param_dict['acct_priv_key'] = args.account_private_key
        print(f'use user given account key at {args.account_private_key}')

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

    return param_dict