from typing import Dict, Any
import json
import logging

import requests

from pyacme.settings import LETSENCRYPT_STAGING
from pyacme.base import _JWSBase, _ACMERequestBase
from pyacme.exceptions import ACMEError


logger = logging.getLogger(__name__)
debug = logger.debug


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


class ACMERequestActions(_ACMERequestBase):
    
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
    badNonce_max_retry = 5
    verify = True
    
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
        _resp = requests.get(cls.dir_url, headers=headers, verify=cls.verify)
        cls.acme_dir = json.loads(_resp.text)
        
    def __init__(self, nonce: Nonce = Nonce()):
        self.nonce = nonce
        
    def _request(self, url: str, method: str, jws: _JWSBase, 
                 headers: Dict[str, Any] = dict()) -> requests.Response:
        """send request to arbitrary url with signed jws"""

        def _retry_for_badNonce(e: ACMEError) -> requests.Response:
            # https://tools.ietf.org/html/rfc8555#section-6.5 p15
            # retry automatically if badNonce error response happens
            # replace the old nonce inside jws
            nonlocal jws, self
            jws.update_jws_nonce(str(e.new_nonce))
            jws.sign()
            # new request with retry for new nonce
            resp = getattr(requests, method.lower())(
                url=url,
                data=json.dumps(jws.post_body),
                headers=headers,
                verify=self.verify
            )
            self.nonce.update_from_resp(resp)
            return resp

        headers.update(self.common_header)
        resp: requests.Response
        resp = getattr(requests, method.lower())(
            url=url,
            data=json.dumps(jws.post_body),
            headers=headers,
            verify=self.verify
        )
        self.nonce.update_from_resp(resp)

        # retry multiple times until badNonce clear
        count = 0
        max_count = self.badNonce_max_retry
        while resp.status_code >= 400 and count <= max_count:
            e = ACMEError(resp)
            if e.type == 'badNonce':
                count += 1
                debug(f'badNonce, retry for {count} time')
                resp = _retry_for_badNonce(e)
            else:
                # do not retry if error type is not badNonce
                break

            ## this does not handle <http-date> format, ignore for now
            # if 'Retry-After' in resp.headers:
            #     time.sleep(float(resp.headers['Retry-After']))

        return resp

    def new_nonce(self, headers: Dict[str, Any] = dict()) -> None:
        """get new nonce explicitly, use HEAD method, expect 200"""
        # no special headers needed
        resp = requests.head(
            self.acme_dir['newNonce'], 
            headers=headers,
            verify=self.verify
        )
        self.nonce.update_from_resp(resp)
        
    def new_account(self, jws: _JWSBase, 
                    headers: Dict[str, Any] = dict()) -> requests.Response:
        """
        create new or query existed account according to given publickey.
        if new account is created, expect 201-created; if account existed, 
        expect 200-OK
        
        see https://tools.ietf.org/html/rfc8555#section-7.3
        """
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