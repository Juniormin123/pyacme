# type:ignore[overload]
from typing import Any, Callable, Dict, Optional, overload
import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa

from pyacme.base import _JWSBase
from pyacme.base import _JWKBase


__all__ = ['JWKRSA']


# combine jws module and jwk module to prevent circular import 


class _JWSRS(_JWSBase):
    
    alg = ''
    hash_method = ''
    
    def __init__(self, 
                 url: str, 
                 nonce: str, 
                 jwk: 'JWKRSA', 
                 kid: str = '', 
                 payload: Dict[str, Any] = dict()):
        # self.jwk: JWKRSA
        if not isinstance(jwk, JWKRSA):
            raise TypeError(
                f'jwk type "{type(jwk)}" not compatible with {self.alg}'
            )
        super().__init__(self.alg, url, nonce, payload, jwk, kid)
    
    def sign(self, hash_algo: Callable) -> None:
        self.jwk: JWKRSA
        sign_input = self.get_sign_input()
        # sig = rsa.sign(sign_input, self.jwk.priv_key, self.hash_method)
        sig = self.jwk.priv_key.sign(
            data=sign_input,
            # PKCS padding for `RS256` signature
            # see https://tools.ietf.org/html/rfc7518#section-3.3
            padding=padding.PKCS1v15(),
            algorithm=hash_algo()
        )
        self.signature = str(
            base64.urlsafe_b64encode(sig).strip(b'='), encoding='utf-8'
        )
        self.post_body['signature'] = self.signature


class JWSRS256(_JWSRS):

    alg = 'RS256'
    hash_method = 'SHA-256'

    def sign(self) -> None:
        return super().sign(hashes.SHA256)


class JWKRSA(_JWKBase):
    
    kty = 'RSA'
    related_JWS = JWSRS256
    
    def __init__(self, priv_key: rsa.RSAPrivateKey, **kwargs):
        """
        private key is need for RSA JWK to generate signature.
        
        following keyword param must be supplied:
         * n: int
         * e: int
        """
        self.n: int
        self.e: int
        self.priv_key = priv_key
        self.priv_key_path = ''
        # update path of private key
        if 'priv_key_path' in kwargs:
            self.priv_key_path = kwargs['priv_key_path']
        super().__init__(self.kty, **kwargs)
    
    def _check_kty_param(self, kwargs: dict) -> None:
        # TODO check type of n, e
        if not "n" in kwargs:
            raise TypeError(f'missing param "n" for key type {self.kty}')
        if not "e" in kwargs:
            raise TypeError(f'missing param "e" for key type {self.kty}')
    
    def _update_container(self) -> None:
        self._container['kty'] = self.kty
        self._container['n'] = self._b64_encode_int(self.n)
        self._container['e'] = self._b64_encode_int(self.e)