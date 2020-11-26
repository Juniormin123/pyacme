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
    
    def __init__(self, 
                 alg: str, 
                 url: str, 
                 nonce: str, 
                 payload: Union[Dict[str, Any], str],
                 jwk: _JWKBase,  
                 kid: str = ''):
        self.alg = alg

        # jwk and kid are exclusive, one of them must be provided
        # see https://tools.ietf.org/html/rfc8555#section-6.2, page 12

        # always provide a `jwk` for now, for storing private key; if `kid` is
        # presented, use `kid` for protected header
        self.jwk = jwk
        self.kid = kid

        self.protected: Dict[str, Any] = {
            'url': url,
            'nonce': nonce,
            'alg': alg,
        }
        if kid:
            self.protected['kid'] = kid
        else:
            self.protected['jwk'] = jwk._container

        self.url = url
        self.nonce = nonce
        # paylaod may be empty `dict()` or empty string `""`
        # see https://tools.ietf.org/html/rfc8555#section-7.5.1 for empty {}
        self.payload = payload
        self.signature = ''
        self.post_body: Dict[str, str] = dict()
    
    def update_jws_nonce(self, new_nonce: str) -> None:
        self.nonce = new_nonce
        self.protected['nonce'] = new_nonce
    
    def get_sign_input(self) -> bytes:
        """
        see https://tools.ietf.org/html/rfc7515#section-2 Signing Input
        """
        protected_json = json.dumps(self.protected)
        protected_b64 = base64.urlsafe_b64encode(
            bytes(protected_json, encoding='utf-8')).strip(b'=')

        # empty payload, see rfc8555 p54 POST example
        # this should not be the literal b'""'
        payload_b64 = b""

        if isinstance(self.payload, (dict, list)):
            # dict or list like payload, empty dict will be json serialized
            payload_json = json.dumps(self.payload)
            payload_b64 = base64.urlsafe_b64encode(
                bytes(payload_json, encoding='utf-8')).strip(b'=')
        elif isinstance(self.payload, str) and bool(self.payload):
            # non-empty string payload
            # see https://tools.ietf.org/html/rfc8555#section-6.3
            payload_b64 = base64.urlsafe_b64encode(
                bytes(self.payload, encoding='utf-8')).strip(b'=')

        self.sign_input = protected_b64 + b'.' + payload_b64

        self.post_body['protected'] = str(protected_b64, encoding='utf-8')
        self.post_body['payload'] = str(payload_b64, encoding='utf-8')
        return self.sign_input
    
    def sign(self) -> None:
        # update signature to self.post_body, str type signature generated
        raise NotImplementedError


class _ACMERespObject:
    """represent an object returned by an acme server"""
    
    def __init__(self, resp: requests.Response, *args, **kwargs):
        # some response may not have content
        self._set_initial(resp)
        self._update_attr(resp, *args, **kwargs)
        # set values for server specified fields that are not in rfc
        # self.__dict__.update(self._raw_resp_body)
    
    def _set_initial(self, resp: requests.Response) -> None:
        self._raw_resp_body = dict()
        if resp.text:
            self._raw_resp_body = json.loads(resp.text)
        self._resp = resp
    
    def _update_attr(self, resp: requests.Response, *args, **kwargs) -> None:
        raise NotImplementedError
    
    def __str__(self):
        # make a copy to prevent changes to origin dict
        cls = type(self).__name__
        _dict = {
            k : v for (k, v) in self.__dict__.items() if not k.startswith('_')
        }
        s = f'{cls}({str(_dict)})'
        return s
    
    __repr__ = __str__