from typing import Dict, Any
import json

import requests

from pyacme.settings import LETSENCRYPT_STAGING
from pyacme.base import _JWSBase


class Nonce:
    """
    Replay-Nonce http header, it can be get from /newNonce or
    returned by the latest response header;
    see https://tools.ietf.org/html/rfc8555#section-7.2
    """
    
    def __init__(self, nonce: str = ''):
        self.latest = nonce
    
    def update(self, nonce: str) -> None:
        self.latest = nonce
    
    def update_from_resp(self, resp: requests.Response) -> None:
        self.latest = resp.headers['Replay-Nonce']
    
    def __str__(self):
        return self.latest
    
    __repr__ = __str__


class ACMERequestActions:
    
    # TODO possible threadsafe solution
    # for nonce updating
    common_header = {
        # https://tools.ietf.org/html/rfc8555#section-6.2
        'Content-Type': 'application/jose+json',
        # 'User-Agent': '',
    }
    # use test as default for now
    dir_url = LETSENCRYPT_STAGING
    acme_dir: Dict[str, str] = dict()
    
    @classmethod
    def set_directory_url(cls, dir_url: str) -> None:
        cls.dir_url = dir_url
    
    @classmethod
    def query_dir(cls, headers: Dict[str, Any] = dict()) -> None:
        """
        update acme server resources, use GET request
        see https://tools.ietf.org/html/rfc8555#section-7.1
        """
        # no special headers needed
        _resp = requests.get(url=cls.dir_url, headers=headers)
        cls.acme_dir = json.loads(_resp.text)
        
    def __init__(self, nonce: Nonce = Nonce()):
        self.nonce = nonce
        
    # TODO exception handle according to
    # https://tools.ietf.org/html/rfc8555#section-6.7
        
    def _request(self, url: str, method: str, jws: _JWSBase, 
                 headers: Dict[str, Any] = dict()) -> requests.Response:
        """send request to arbitrary url with signed jws"""
        headers.update(self.common_header)
        resp = getattr(requests, method.lower())(
            url=url,
            data=json.dumps(jws.post_body),
            headers=headers
        )
        self.nonce.update_from_resp(resp)
        return resp

    def new_nonce(self, headers: Dict[str, Any] = dict()) -> None:
        """get new nonce explicitly, use HEAD method, expect 200"""
        # no special headers needed
        resp = requests.head(self.acme_dir['newNonce'], headers=headers)
        self.nonce.update_from_resp(resp)
        
    def new_account(self, jws: _JWSBase, 
                    headers: Dict[str, Any] = dict()) -> requests.Response:
        """
        create new or query existed account according to given publickey.
        if new account is created, expect 201-created; if account existed, 
        expect 200-OK
        
        see https://tools.ietf.org/html/rfc8555#section-7.3
        """
        # headers.update(self.common_header)
        # resp = requests.post(
        #     url=self.acme_dir['newAccount'], 
        #     data=json.dumps(jws.post_body),
        #     headers=headers
        # )
        # self.nonce.update_from_resp(resp)
        resp = self._request(
            url=self.acme_dir['newAccount'],
            method='post',
            jws=jws,
            headers=headers
        )
        return resp
    
    def key_change(self, jws: _JWSBase,
                   headers: Dict[str, Any] = dict()) -> requests.Response:
        """
        key rollover request, expect 200-OK on successful change; if new key
        already existed in server with another account, 409-Conflict will 
        return.
        
        see https://tools.ietf.org/html/rfc8555#section-7.3.5 page 43
        """
        resp = self._request(
            url=self.acme_dir['keyChange'],
            method='post',
            jws=jws,
            headers=headers
        )
        return resp

    def new_order(self, jws: _JWSBase,
                  headers: Dict[str, Any] = dict()) -> requests.Response:
        """
        order creation request, expect 201-created if new order is created
        successfully; header `Location` will return, containing an url to the
        created order resources.

        see https://tools.ietf.org/html/rfc8555#section-7.4, page 45-46
        """
        resp = self._request(
            url=self.acme_dir['newOrder'],
            method='post',
            jws=jws,
            headers=headers
        )
        return resp