import base64
import subprocess
import hashlib
import json
from typing import List

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

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
    subj = f'/CN={domains[0]}' + names
    # private key that is different from the account private key should be used
    if not privkey_path:
        # create a private key if not given
        csr_priv_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        # TODO proper way to store generated csr private key
        csr_priv_key_b = csr_priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open('csr_privkey.pem', 'wb') as f:
            f.write(csr_priv_key_b)
        privkey_path = 'csr_privkey.pem'

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
