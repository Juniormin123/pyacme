# import rsa
from cryptography.hazmat.primitives.asymmetric import rsa

from pyacme.base import _JWKBase


class JWKRSA(_JWKBase):
    
    kty = 'RSA'
    
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