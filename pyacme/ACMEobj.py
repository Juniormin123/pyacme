from typing import Dict, List
import requests

from pyacme.base import _ACMERespObject
from pyacme.base import _JWKBase


class Empty(_ACMERespObject):
    """represent an empty acme response object"""

    def _update_attr(self, resp: requests.Response, *args, **kwargs) -> None:
        pass


class ACMEAccount(_ACMERespObject):
    """
    An acme account resource, attr `acct_location` is added in addition to
    other rfc specified fields. 

    see https://tools.ietf.org/html/rfc8555#section-7.1.2
    """
    
    def _update_attr(self, resp: requests.Response, *args, **kwargs):
        # field and type defined by RFC8555
        attrs = [
            # (field_name, default_value if server not provided)
            ('status', ''),
            ('contact', list()),
            ('termsOfServiceAgreed', ''),       # boolean
            ('externalAccountBinding', dict()), # object
            ('orders', '')
        ]
        for attr in attrs:
            if not (attr[0] in self._raw_resp_body):
                # set default value for rfc8555 stated attr
                setattr(self, attr[0], attr[1])

        if not hasattr(self, 'acct_location'):
            # when updating an acct obj itself, if location already exist
            # then do not give initial value
            self.acct_location = ''
        if 'Location' in resp.headers:
            # sometimes server resp header may not include `"Location"` header,
            # when making account update request
            self.acct_location = resp.headers['Location']
        
        # in case server return some attrs which are not included in rfc8555
        self.__dict__.update(self._raw_resp_body)
    
    def update(self, resp: requests.Response) -> None:
        """update the accout instance by accepting new response"""
        self._set_initial(resp)
        self._update_attr(resp)
    
    def set_order(self, order_obj: 'ACMEOrder') -> None:
        self._order_obj = order_obj
    
    def set_jwk(self, jwk: _JWKBase) -> None:
        self._jwk_obj = jwk
    
    def set_auth(self, auth_list: List['ACMEAuthorization']) -> None:
        self._auth_objs = auth_list
    
    @property
    def order_obj(self) -> 'ACMEOrder':
        return self._order_obj

    @property
    def auth_objs(self) -> List['ACMEAuthorization']:
        return self._auth_objs

    @property
    def jwk_obj(self) -> '_JWKBase':
        return self._jwk_obj


class ACMEOrder(_ACMERespObject):
    """
    An acme order object, attr `order_location` is added in addition to other
    rfc specified fields.

    see https://tools.ietf.org/html/rfc8555#section-7.1.3
    """

    def _update_attr(self, resp: requests.Response, *args, **kwargs) -> None:
        # field and type defined by RFC8555
        attrs = [
            ('status', ''),             # required
            ('expires', ''),

            # identifiers: list of dict, which must contain "type", "value"
            # [{'type': str, 'value': ''}, ...]
            # see rfc8555 p26
            ('identifiers', list()),    # array of objects

            ('notBefore', ''),
            ('notAfter', ''),
            ('error', ''),

            # contains location for auth objects
            ('authorizations', list()), # required, array of strings

            ('finalize', ''),           # required
            ('certificate', '')
        ]
        for attr in attrs:
            if not (attr[0] in self._raw_resp_body):
                setattr(self, attr[0], attr[1])
        
        if not hasattr(self, 'order_location'):
            self.order_location = ''
        if 'Location' in resp.headers:
            self.order_location = resp.headers['Location']

        self.__dict__.update(self._raw_resp_body)
    
    def update(self, resp: requests.Response) -> None:
        self._set_initial(resp)
        self._update_attr(resp)


class ACMEAuthorization(_ACMERespObject):
    """
    An acme authorization object, attr `auth_location` is added in addition 
    to other rfc specified fields.

    see https://tools.ietf.org/html/rfc8555#section-7.1.4
    """
    # def __init__(self, resp: requests.Response, *args, **kwargs) -> None:
    #     super().__init__(resp, *args, **kwargs)
    #     self._update_chall()

    def _update_attr(self, resp: requests.Response, *args, **kwargs) -> None:
        # field and type defined by RFC8555
        attrs = [
            ('status', ''),             # required
            ('expires', ''),

            # identifier: dict, which must contain "type", "value"
            # {'type': str, 'value': ''}
            # see rfc8555 p29
            ('identifier', dict()),     # object

            # challenge: list of dict, may be decided by server
            ('challenges', list()),     # required, array of objects

            ('wildcard', '')            # boolean
        ]
        for attr in attrs:
            if not (attr[0] in self._raw_resp_body):
                setattr(self, attr[0], attr[1])
        
        if not hasattr(self, 'auth_location'):
            self.auth_location = ''
        # auth location comes from order object's authorization field
        if 'auth_url' in kwargs:
            self.auth_location = kwargs['auth_url']

        self.__dict__.update(self._raw_resp_body)
        self._set_chall_objs()
    
    def _set_chall_objs(self) -> None:
        # add challenge object
        _resp_body = self._raw_resp_body
        self._chall_objs: List['ACMEChallenge'] = []
        if 'challenges' in _resp_body:
            for chall_dict in _resp_body['challenges']:
                self._chall_objs.append(ACMEChallenge(chall_dict=chall_dict))
    
    @property
    def chall_objs(self) -> List['ACMEChallenge']:
        return self._chall_objs
    
    def update(self, resp: requests.Response, **kwargs) -> None:
        """update the auth instance by accepting new response"""
        self._set_initial(resp)
        self._update_attr(resp, **kwargs)


class ACMEChallenge(_ACMERespObject):
    """
    see https://tools.ietf.org/html/rfc8555#section-8
    """
    def __init__(self, *args, **kwargs) -> None:
        # https://tools.ietf.org/html/rfc8555#section-7.5.1 p55
        # chall object may be updated by server and returned as response when
        # client responded to a Challenge;
        # provide two constuct methods
        if 'resp' in kwargs:
            self._set_initial(kwargs['resp'])
            self._update_attr(kwargs['resp'])
        if 'chall_dict' in kwargs:
            self._init_by_dict(kwargs['chall_dict'])
    
    def _init_by_dict(self, chall_dict: Dict[str, str]) -> None:
        self.type = ''
        self.url = ''
        self.status = ''
        self.token = ''
        self.validated = ''
        self.error = ''
        self.update_by_dict(chall_dict)
    
    def _update_attr(self, resp: requests.Response, *args, **kwargs) -> None:
        attrs = [
            # required below
            ('type', ''),
            ('url', ''),
            ('status', ''),
            # optional below
            ('token', ''),
            ('validated', ''),
            ('error', '')
        ]
        for attr in attrs:
            if not (attr[0] in self._raw_resp_body):
                setattr(self, attr[0], attr[1])
        
        self.__dict__.update(self._raw_resp_body)
    
    def update_by_dict(self, chall_dict: Dict[str, str]) -> None:
        self.__dict__.update(chall_dict)

    def update_by_resp(self, resp: requests.Response) -> None:
        self._set_initial(resp)
        self._update_attr(resp)
    