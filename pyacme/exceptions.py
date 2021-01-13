"""see https://tools.ietf.org/html/rfc8555#section-6.7"""

from typing import List, Dict, Any
import json

import requests

# from pyacme.ACMEobj import Empty


class ACMEError(Exception):
    """see https://tools.ietf.org/html/rfc8555#section-6.7"""

    def __init__(self, resp: requests.Response) -> None:
        self.status_code: int
        self.type = ''
        self._resp = resp
        self.subproblems: List[Dict[str, Any]] = []
        self._update_exeception(resp)

    def _update_exeception(self, resp: requests.Response) -> None:
        cls = type(self)
        self._status_code = resp.status_code
        if resp.text:
            _content = json.loads(resp.text)
            # type e.g. "urn:ietf:params:acme:error:badCSR"
            if 'type' in _content:
                self.type = _content['type'].split(':')[-1]
                _content.pop('type')
            if 'subproblems' in _content:
                self.subproblems = _content['subproblems']
                _content.pop('subproblems')
            # load rest attributes
            self.__dict__.update(_content)
            # if badNonce error raised, new nonce should be returned by server
            if 'Replay-Nonce' in resp.headers:
                self.new_nonce = resp.headers['Replay-Nonce']
    
    @property
    def status_code(self) -> int:
        return self._status_code
    
    def __str__(self) -> str:
        cls = type(self).__name__
        _dict = {
            k : v for (k, v) in self.__dict__.items() if not k.startswith('_')
        }
        s = f'{cls}[{self.type} {self._status_code}]({str(_dict)})'
        return s