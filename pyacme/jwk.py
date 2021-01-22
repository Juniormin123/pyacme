# type:ignore[overload]
from typing import Any, Callable, Dict, Optional, overload, Type
import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from pyacme.base import _JWSBase, _JWKBase


__all__ = ['JWKRSA', 'JWKES256']


# combine jws module and jwk module to prevent circular import 

# pebble supported alg: 
# https://github.com/letsencrypt/pebble/blob/8a79a257176b5dd587242fb5f524213abc5fd1a7/wfe/jose.go#L17


class _JWSRS(_JWSBase):
    
    alg = ''
    hash_method = ''
    
    def __init__(self, 
                 url: str, 
                 nonce: str, 
                 jwk: 'JWKRSA', 
                 kid: str = '', 
                 payload: Dict[str, Any] = dict()):
        if not isinstance(jwk, JWKRSA):
            raise TypeError(
                f'jwk type "{type(jwk)}" not compatible with {self.alg}'
            )
        super().__init__(self.alg, url, nonce, payload, jwk, kid)
    
    def sign(self, hash_algo: Callable) -> None:
        self.jwk: JWKRSA
        sign_input = self.get_sign_input()
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


# ES jwk


class _JWSES(_JWSBase):

    alg = ''
    hash_method = ''

    def __init__(self, 
                 url: str, 
                 nonce: str, 
                 jwk: '_JWKESBase', 
                 kid: str, 
                 payload: Dict[str, Any],
                 jwk_target_type: Type):
        if not isinstance(jwk, jwk_target_type):
            raise TypeError(
                f'jwk type "{type(jwk)}" not compatible with {self.alg}'
            )
        super().__init__(self.alg, url, nonce, payload, jwk, kid)
    
    def sign(self, hash_algo: Callable, r_size: int, s_size: int) -> None:
        self.jwk: _JWKESBase
        sign_input = self.get_sign_input()

        # the sign() is asn.1 encoded, does not compatible with rfc7515/7518
        sig = self.jwk.priv_key.sign(
            data=sign_input,
            signature_algorithm=ec.ECDSA(hash_algo())
        )
        # https://tools.ietf.org/html/rfc7515#appendix-A.3.1
        # directly use r and s to construct the signature
        r, s = utils.decode_dss_signature(sig)
        r_byte, s_byte = r.to_bytes(r_size, 'big'), s.to_bytes(s_size, 'big')
        r_s = r_byte + s_byte

        self.signature = str(
            base64.urlsafe_b64encode(r_s).strip(b'='), encoding='utf-8'
        )
        self.post_body['signature'] = self.signature


class _JWKESBase(_JWKBase):

    kty = 'EC'
    related_JWS = _JWSES

    def __init__(self, priv_key: ec.EllipticCurvePrivateKey, **kwargs):
        """
        see https://tools.ietf.org/html/rfc7518#section-6.2

        following keyword param must be supplied:
         * x: int
         * y: int
        """
        self.x: int
        self.y: int
        self.priv_key = priv_key
        self.crv = kwargs['crv']
        super().__init__(self.kty, **kwargs)
    
    def _check_kty_param(self, kwargs: dict) -> None:
        if not "x" in kwargs:
            raise TypeError(f'missing param "x" for key type {self.kty}')
        if not "y" in kwargs:
            raise TypeError(f'missing param "y" for key type {self.kty}')

    def _update_container(self) -> None:
        self._container['kty'] = self.kty
        self._container['x'] = self._b64_encode_int(self.x)
        self._container['y'] = self._b64_encode_int(self.y)
        self._container['crv'] = self.crv


class JWSES256(_JWSES):

    alg = 'ES256'
    hash_method = 'SHA-256'

    def __init__(self, 
                 url: str, 
                 nonce: str, 
                 jwk: 'JWKES256', 
                 kid: str = '', 
                 payload: Dict[str, Any] = dict()):
        super().__init__(url, nonce, jwk, kid, payload, JWKES256)
    
    def sign(self) -> None:
        return super().sign(hashes.SHA256, 32, 32)


class JWKES256(_JWKESBase):

    related_JWS = JWSES256

    def __init__(self, priv_key: ec.EllipticCurvePrivateKey, **kwargs):
        x = priv_key.public_key().public_numbers().x
        y = priv_key.public_key().public_numbers().y
        super().__init__(priv_key, x=x, y=y, crv='P-256', **kwargs)

