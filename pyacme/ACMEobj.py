import requests

from pyacme.base import _ACMERespObject

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
        self._get_location(resp)

    def _get_location(self, resp: requests.Response):
        self.acct_location = resp.headers['Location']