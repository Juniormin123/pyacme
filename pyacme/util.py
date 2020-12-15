import base64
import subprocess
import hashlib
import json
from typing import List
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import requests

from pyacme.base import _JWKBase


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


def generate_rsa_privkey(privkey_dir: str, 
                         keysize = 2048,
                         key_name = 'certkey.key') -> None:
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


def parse_csr(privkey_path: str, 
              domains: List[str], 
              extra: List[str] = [], 
              **subjects: str) -> bytes:
    """
    `domains` will be added to csr using `-addtext` option of openssl, 
    other subject names for `openssl req` list as below

     * C = Country, like GB;
     * ST = State or Province
     * L  = Locality
     * O  = Organization Name        
     * OU = Organizational Unit Name
     * emailAddress = test@email.address

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