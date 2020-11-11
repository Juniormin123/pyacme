from typing import Dict, Any, Optional, Union, List
import base64
import json

import requests


class _JWKBase: 
    """JWK object is a memeber of protected header and then encoded by b64"""
    
    def __init__(self, kty: str, **kwargs):
        # _container will be serialised by json then b64 encoded
        self._container: Dict[str, Any] = dict()
        self.kty = kty
        self._check_kty_param(kwargs)
        self.__dict__.update(kwargs)
        self._update_container()
    
    def _check_kty_param(self, kwargs: dict) -> None:
        # TODO abstractmethod
        raise NotImplementedError

    def _update_container(self) -> None:
        # TODO abstractmethod
        raise NotImplementedError
    
    @staticmethod
    def _b64_encode_int(i: int) -> str:
        """
        encode an int using urlsafe base64; hex the int to get string form and
        then transform into bytes for b64 encoding
        """
        hexed = hex(i)[2:]
        if len(hexed) % 2 != 0:
            hexed = '0' + hexed
        i_bytes = bytes.fromhex(hexed)
        b64_encoded = base64.urlsafe_b64encode(i_bytes).strip(b'=')
        return str(b64_encoded, encoding='utf-8')
    
    def __str__(self):
        return str(self._container)
    
    __repr__ = __str__


class _JWSBase:
    
    def __init__(self, alg: str, url: str, nonce: str, 
                 jwk: _JWKBase, payload: Dict[str, Any]):
        self.alg = alg
        self.jwk = jwk
        self.url = url
        self.nonce = nonce
        self.payload = payload
        self.protected = {
            'url': url,
            'nonce': nonce,
            'alg': alg,
            'jwk': jwk._container
        }
        self.signature = ''
        self.post_body: Dict[str, str] = dict()
    
    def get_sign_input(self) -> bytes:
        protected_json = json.dumps(self.protected)
        protected_b64 = base64.urlsafe_b64encode(
            bytes(protected_json, encoding='utf-8')).strip(b'=')
        payload_json = json.dumps(self.payload)
        payload_b64 = base64.urlsafe_b64encode(
            bytes(payload_json, encoding='utf-8')).strip(b'=')
        # https://tools.ietf.org/html/rfc7515#section-2 Signing Input
        self.sign_input = protected_b64 + b'.' + payload_b64
        # TODO proper behaviour when payload is empty
        self.post_body['protected'] = str(protected_b64, encoding='utf-8')
        self.post_body['payload'] = str(payload_b64, encoding='utf-8')
        return self.sign_input
    
    def sign(self) -> None:
        # update signature to self.post_body
        raise NotImplementedError


class _ACMERespObject:
    """represent an object returned by an acme server"""
    
    def __init__(self, resp: requests.Response):
        # should not be empty
        self._raw_resp_body = json.loads(resp.text)
        self._resp = resp
        self._update_attr(resp)
        # set values for server specified fields that are not in rfc
        self.__dict__.update(self._raw_resp_body)
    
    def _update_attr(self, *args, **kwargs) -> None:
        raise NotImplementedError
    
    def __str__(self):
        # make a copy to prevent changes to origin dict
        _dict = dict(self.__dict__)
        for k in [i for i in _dict if i.startswith('_raw')]:
            _dict.pop(k)
        return str(_dict)
    
    __repr__ = __str__