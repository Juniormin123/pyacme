import base64
import subprocess
import hashlib
import json
from typing import List

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

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
              CN: str, 
              extra: List[str] = [], 
              **subjects: str) -> bytes:
    """
    subject names for `openssl req`, 
    `CN` is required
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
    subj = f'/CN={CN}' + names
    output_p = subprocess.run(
        [
            'openssl', 'req', '-new', 
            '-key', privkey_path,
            '-outform', 'DER', 
            '-subj', subj,
            *extra
        ],
        capture_output=True,
        check=True
    )
    output_b = output_p.stdout
    return output_b
