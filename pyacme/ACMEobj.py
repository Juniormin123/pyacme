from typing import Dict, List
import requests

from pyacme.base import _ACMERespObject


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
            ('termsOfServiceAgreed', ''),    # boolean
            ('externalAccountBinding', dict()), # object
            ('orders', '')
        ]
        for attr in attrs:
            if not (attr[0] in self._raw_resp_body):
                setattr(self, attr[0], attr[1])

        self.acct_location = ''
        if 'Location' in resp.headers:
            # sometimes server resp header may not include `"Location"` header,
            # when making account update request
            self.acct_location = resp.headers['Location']
    
    def set_order(self, order_obj: 'ACMEOrder') -> None:
        self.order = order_obj


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
            ('authorizations', list()), # required, array of strings
            ('finalize', ''),           # required
            ('certificate', '')
        ]
        for attr in attrs:
            if not (attr[0] in self._raw_resp_body):
                setattr(self, attr[0], attr[1])
        
        self.order_location = ''
        if 'Location' in resp.headers:
            self.order_location = resp.headers['Location']


class ACMEAuthorization(_ACMERespObject):
    """
    An acme authorization object, attr `auth_location` is added in addition 
    to other rfc specified fields.

    see https://tools.ietf.org/html/rfc8555#section-7.1.4
    """
    def __init__(self, resp: requests.Response, *args, **kwargs) -> None:
        super().__init__(resp, *args, **kwargs)
        self._update_chall()

    def _update_attr(self, resp: requests.Response, *args, **kwargs) -> None:
        # field and type defined by RFC8555
        attrs = [
            ('status', ''),             # required
            ('expires', ''),

            # identifier: dict, which must contain "type", "value"
            # {'type': str, 'value': ''}
            # see rfc8555 p29
            ('identifier', dict()),    # object

            # challenge: list of dict, may be decided by server
            ('challenges', list()),     # required, array of objects

            ('wildcard', '')            # boolean
        ]
        for attr in attrs:
            if not (attr[0] in self._raw_resp_body):
                setattr(self, attr[0], attr[1])
        
        self.auth_location = ''
        if 'Location' in resp.headers:
            self.auth_location = resp.headers['Location']
        
    def _update_chall(self) -> None:
        # add challenge object
        self.challenges: List['ACMEChallenge'] = []
        if 'challenges' in self._raw_resp_body:
            for chall_dict in self._raw_resp_body['challenges']:
                self.challenges.append(ACMEChallenge(chall_dict))


class ACMEChallenge:
    """
    see https://tools.ietf.org/html/rfc8555#section-8
    """

    def __init__(self, chall_dict: Dict[str, str] = dict()) -> None:
        # required field defined in rfc8555 section-8
        self.type = ''
        self.url = ''
        self.status = ''
        # optional field
        self.token = ''
        self.validated = ''
        self.error = ''

        if chall_dict:
            self.__dict__.update(chall_dict)
    
    def __str__(self) -> str:
        cls = type(self).__name__
        return f'{cls}({str(self.__dict__)})'
    
    __repr__ = __str__