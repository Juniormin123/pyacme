from typing import Dict, List, Optional, Union
import requests
import json

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey

from pyacme.base import _ACMERespObject, _AcctActionBase, _JWKBase
from pyacme.util import save_cert


__all__ = ['ACMEAccount', 'ACMEOrder', 'ACMEAuthorization', 'ACMEChallenge']


class Empty(_ACMERespObject):
    """represent an empty acme response object"""

    def _update_attr(self, resp: requests.Response, *args, **kwargs) -> None:
        pass


class ACMEAccount(_ACMERespObject):
    """
    An acme account resource, attr `acct_location` is added in addition to
    other rfc specified fields. 
     * pass key-word argument `jwk` to bind a key with the acct_obj
     * pass key-word argument `acct_actions` to bind an `ACMEAccountActions`
     class for an acct_obj

    see https://tools.ietf.org/html/rfc8555#section-7.1.2
    """

    def __init__(self, resp: requests.Response, *args, **kwargs):
        self._order_objs: List['ACMEOrder']
        self.status: str
        self.contact: List[str]
        self.termsOfServiceAgreed: str
        self.externalAccountBinding: Dict[str, str]
        self.orders: str
        super().__init__(resp, *args, **kwargs)

    @classmethod
    def init_by_query(cls, 
                      jwk: _JWKBase, 
                      *, 
                      acct_actions: _AcctActionBase) -> 'ACMEAccount':
        """
        form an `ACMEAccount` instance given a `jwk`, will perform `new_acct` 
        request to server, query if the jwk has an associated account, if not
        then use another request to create one.
        """
        resp = acct_actions.query_acct(jwk, jwk.related_JWS)
        return cls(resp, acct_actions=acct_actions, jwk=jwk)
    
    @classmethod
    def init_by_create(cls, 
                       jwk: _JWKBase,
                       *,
                       acct_actions: _AcctActionBase,
                       contact: List[str]) -> 'ACMEAccount':
        """
        create a new account by given a public key and contact info
        """
        resp = acct_actions.create_acct(
            jwk, contact, jwk.related_JWS
        )
        return cls(resp, acct_actions=acct_actions, jwk=jwk)
    
    def poll_acct_state(self, update_orders: bool = True) -> None:
        """
        update account status by sending post-as-get request to acct location
        """
        if update_orders:
            self.get_orders()
        resp = self.acct_actions.post_as_get(
            url=self.acct_location,
            acct_obj=self,
            jws_type=self.jwk_obj.related_JWS
        )
        self._update_from_resp(resp)
    
    def new_order(self, 
                  *, 
                  identifiers: List[str], 
                  not_before: str = '', 
                  not_after: str = '') -> 'ACMEOrder':
        """
        create new order by giving identifiers
        """
        iden_list = [dict(type='dns', value=i) for i in identifiers]
        resp = self.acct_actions.new_order(
            acct_obj=self,
            identifiers=iden_list,
            not_before=not_before,
            not_after=not_after,
            jws_type=self.jwk_obj.related_JWS
        )
        order_obj = ACMEOrder(resp, related_acct=self)
        self._order_objs.append(order_obj)
        return order_obj
    
    def get_orders(self) -> List['ACMEOrder']:
        """
        iterate through `orders` field of the acct_obj and fill `order_objs`, 
        only orders with state `"pending"` and `"valid"` will return; 
         * may need multiple requests to fetch poll orders, use 
         `requests.Response.links` to handle possible pagination

        see https://tools.ietf.org/html/rfc8555#section-7.1.2.1 Orders List
        """

        def _post_as_get(url: str, order = False) -> requests.Response:
            resp = self.acct_actions.post_as_get(
                url=url, 
                acct_obj=self,
                jws_type=self.jwk_obj.related_JWS
            )
            if order:
                # handling response from post-as-get to an order url;
                # order location may not appear in an non-creation response,
                # add the location back for ACMEOrder constructor
                if not 'Location' in resp.headers:
                    resp.headers['Location'] = url
            return resp

        # get Orders List object by sending post-as-get to "orders" url
        orders_resp = _post_as_get(self.orders)
        url_poll: List[str] = json.loads(orders_resp.text)['orders']

        while 'next' in orders_resp.links:
            url_next = orders_resp.links['next']['url']
            orders_resp = _post_as_get(url_next)
            url_poll += json.loads(orders_resp.text)['orders']
        

        for order_url in url_poll:
            for existed_order_obj in self.order_objs:
                # if an order_obj already exists, call poll_order_state() on it
                if existed_order_obj.order_location == order_url:
                    existed_order_obj.poll_order_state()
                    break
            else:
                # add new order_obj to the acct_obj
                resp = _post_as_get(order_url, order=True)
                order_obj = ACMEOrder(resp, related_acct=self)
                self._order_objs.append(order_obj)
        
        return self.order_objs
    
    def update_account(self, *, contact: List[str], **kwargs) -> None:
        """
        update account info, usaually the contact field;
        change or add email contacts
         * `"contact"`: list of string like `["mailto:test@mail.com"]`
        """
        resp = self.acct_actions.update_acct(
            acct_obj=self,
            jws_type=self.jwk_obj.related_JWS,
            **{'contact': contact, **kwargs}
        )
        self.poll_acct_state()
    
    def account_key_rollover(self, jwk_new: _JWKBase) -> None:
        """change account's pubkey to a new one"""
        resp = self.acct_actions.acct_key_rollover(
            acct_obj=self,
            jwk_new=jwk_new,
            jws_type=self.jwk_obj.related_JWS
        )
        self._set_jwk(jwk_new)
        # new jwk must be used to send post-as-get
        self.poll_acct_state()
    
    def deactivate(self) -> None:
        """
        deactivate the account; after deactivation, 401-Unauthorizaed will
        return from server if any POST or POST-as-GET is sent by the acct.
        """
        resp = self.acct_actions.deactivate_acct(
            acct_obj=self,
            jws_type=self.jwk_obj.related_JWS
        )
        self._update_from_resp(resp)
    
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

        if 'acct_actions' in kwargs:
            self.acct_actions: _AcctActionBase = kwargs['acct_actions']

        if 'jwk' in kwargs:
            self._set_jwk(kwargs['jwk'])
        
        if not hasattr(self, '_order_objs'):
            self._order_objs = list()
        
        # in case server return some attrs which are not included in rfc8555
        self.__dict__.update(self._raw_resp_body)
    
    def _update_from_resp(self, resp: requests.Response) -> None:
        """update the accout instance by accepting new response"""
        self._set_initial(resp)
        self._update_attr(resp)
    
    def _set_jwk(self, jwk: _JWKBase) -> None:
        self._jwk_obj = jwk
    
    @property
    def order_objs(self) -> List['ACMEOrder']:
        return self._order_objs

    @property
    def jwk_obj(self) -> '_JWKBase':
        return self._jwk_obj


class ACMEOrder(_ACMERespObject):
    """
    An acme order object, attr `order_location` is added in addition to other
    rfc specified fields.
     * pass key-word argument `related_acct` to bind order_obj to an acct_obj

    see https://tools.ietf.org/html/rfc8555#section-7.1.3
    """

    def __init__(self, resp: requests.Response, *args, **kwargs):
        self.status: str
        self.expires: str
        self.notBefore: str
        self.notAfter: str
        self.error: str
        self.identifiers: List[Dict[str, str]]
        self.authorizations: List[str]
        self.finalize: str
        self.certificate: str
        super().__init__(resp, *args, **kwargs)

    def poll_order_state(self) -> None:
        """
        use POST-as-GET to poll and update the `ACMEOrder` object, lastest
        `"authorizations"` and `"status"` are expected
        """
        act = self.related_acct.acct_actions
        jws_type = self.related_acct.jwk_obj.related_JWS
        resp = act.post_as_get(
            url=self.order_location,
            acct_obj=self.related_acct,
            jws_type=jws_type
        )
        self._update_from_resp(resp)
    
    def finalize_order(self, 
                       privkey: Union[RSAPrivateKey, EllipticCurvePrivateKey], 
                       **subject_names) -> None:
        """
        finalize the `ACMEOrder` order by sending to its `"finalize"` url
        """
        act = self.related_acct.acct_actions
        jws_type = self.related_acct.jwk_obj.related_JWS
        resp = act.finalize_order(
            self, 
            privkey=privkey,
            domains=self.identifier_values,
            subject_names=subject_names,
            jws_type=jws_type
        )
        self._update_from_resp(resp)

    def download_certificate(self, 
                             cert_dir: str,
                             cert_fmt = 'pem-certificate-chain'
                             ) -> requests.Response:
        """
        download certificate for an valid order.
        `cer_fmt` can be one of the following:
         * `pem-certificate-chain`
         * `pkix-cert`
         * `pkcs7-mime`

        see https://tools.ietf.org/html/rfc8555#section-7.4.2
        """
        header = {'Accept': f'application/{cert_fmt}'}
        if cert_fmt == 'pem-certificate-chain':
            resp = self._related_acct.acct_actions.post_as_get(
                url=self.certificate,
                acct_obj=self.related_acct,
                jws_type=self.related_acct.jwk_obj.related_JWS
            )
            resp = save_cert(resp, cert_dir)
            return resp
        # TODO
        # elif cert_fmt == 'pkix-cert':
        #     pass
        # elif cert_fmt == 'pkcs7-mime':
        #     pass
        else:
            raise ValueError(f'unrecognized cert format: {cert_fmt}')


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

        if 'related_acct' in kwargs:
            self._set_related_acct(kwargs['related_acct'])

        self.__dict__.update(self._raw_resp_body)
        
        self.identifier_values = [i['value'] for i in self.identifiers]

        self._fetch_auth()
    
    def _fetch_auth(self) -> None:
        """when updating order, auth_objs of this order will all be updated"""
        act = self.related_acct.acct_actions
        self._auth_objs: List['ACMEAuthorization'] = []
        for auth_url in self.authorizations:
            resp = act.post_as_get(
                url=auth_url,
                acct_obj=self.related_acct,
                jws_type=self.related_acct.jwk_obj.related_JWS
            )
            self._auth_objs.append(
                ACMEAuthorization(
                    resp=resp, 
                    related_order=self,
                    auth_url=auth_url
                )
             )
    
    def _update_from_resp(self, resp: requests.Response) -> None:
        self._set_initial(resp)
        self._update_attr(resp)

    @property
    def auth_objs(self) -> List['ACMEAuthorization']:
        if not hasattr(self, '_auth_objs'):
            return list()
        return self._auth_objs

    def _set_related_acct(self, acct_obj: ACMEAccount) -> None:
        self._related_acct = acct_obj
    
    @property
    def related_acct(self) -> ACMEAccount:
        return self._related_acct


class ACMEAuthorization(_ACMERespObject):
    """
    An acme authorization object, attr `auth_location` is added in addition 
    to other rfc specified fields.
     * pass key-word argument `related_order` to bind auth_obj to an order_obj
     * pass key-word argument `auth_url` to set this auth_obj's location

    see https://tools.ietf.org/html/rfc8555#section-7.1.4
    """
    def __init__(self, resp: requests.Response, *args, **kwargs) -> None:
        self.status: str
        self.expires: str
        self.identifier: Dict[str, str]
        self.challenges: List[str]
        self.wildcard: str
        super().__init__(resp, *args, **kwargs)

    def poll_auth_state(self) -> None:
        """
        use POST-as-GET to poll and update the `ACMEAuthorization` object,
        `ACMEChallenge` object related to auth will be updated as well
        """
        act = self.related_order.related_acct.acct_actions
        jws_type = self.related_order.related_acct.jwk_obj.related_JWS
        resp = act.post_as_get(
            url=self.auth_location,
            acct_obj=self.related_order.related_acct,
            jws_type=jws_type
        )
        self._update_from_resp(resp)
        # TODO status become deactivated, other fields will be empty
    
    def deactivate_auth(self) -> None:
        """
        deactivate one `ACMEAuthorization` object

        see https://tools.ietf.org/html/rfc8555#section-7.5.2
        """
        act = self.related_order.related_acct.acct_actions
        jws_type = self.related_order.related_acct.jwk_obj.related_JWS
        resp = act.deactivate_auth(self, jws_type=jws_type)
        self._update_from_resp(resp)

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

        if 'related_order' in kwargs:
            self._set_related_order(kwargs['related_order'])

        self.__dict__.update(self._raw_resp_body)

        self.identifier_value = self.identifier['value']

        self._set_chall_objs()
    
    def _set_chall_objs(self) -> None:
        # add challenge object
        _resp_body = self._raw_resp_body
        self._chall_objs: List['ACMEChallenge'] = []
        if 'challenges' in _resp_body:
            for chall_dict in _resp_body['challenges']:
                self._chall_objs.append(
                    ACMEChallenge(
                        chall_dict=chall_dict,
                        related_auth=self
                    )
                )

        # set chall_obj for each type
        for chall_obj in self._chall_objs:
            if 'http' in chall_obj.type.lower():
                self.chall_http = chall_obj
            elif 'dns' in chall_obj.type.lower():
                self.chall_dns = chall_obj
            elif 'tls-alpn' in chall_obj.type.lower():
                self.chall_tls_alpn = chall_obj
    
    @property
    def chall_objs(self) -> List['ACMEChallenge']:
        if not hasattr(self, '_chall_objs'):
            return list()
        return self._chall_objs
    
    def _update_from_resp(self, resp: requests.Response, **kwargs) -> None:
        """update the auth instance by accepting new response"""
        self._set_initial(resp)
        self._update_attr(resp, **kwargs)

    def _set_related_order(self, order_obj: ACMEOrder) -> None:
        self._related_order = order_obj
    
    @property
    def related_order(self) -> ACMEOrder:
        return self._related_order


class ACMEChallenge(_ACMERespObject):
    """
    rfc8555 provides no method to poll `ACMEChallenge`, poll related
    `ACMEAuthorization` object to get latest challenge.
     * pass key-word argument `related_auth` to bind chall_obj to an auth_obj

    see https://tools.ietf.org/html/rfc8555#section-8
    """
    def __init__(self, 
                 *, 
                 resp: Optional[requests.Response] = None, 
                 chall_dict: Dict[str, str] = dict(),
                 **kwargs) -> None:
        # https://tools.ietf.org/html/rfc8555#section-7.5.1 p55
        # chall object may be updated by server and returned as response when
        # client responded to a Challenge;
        self.type: str
        self.url: str
        self.status: str
        self.token: str
        self.validated: str
        self.error: str
        if isinstance(resp, requests.Response):
            self._set_initial(resp)
            self._update_attr(resp, **kwargs)
        if chall_dict:
            self._init_by_dict(chall_dict, **kwargs)
    
    def respond(self) -> 'ACMEChallenge':
        """
        respond to this challenge's `"url"` attribute
        """
        acct_obj = self.related_auth.related_order.related_acct
        act = acct_obj.acct_actions
        jws_type = acct_obj.jwk_obj.related_JWS
        resp = act.respond_to_challenge(self, jws_type=jws_type)
        return type(self)(resp=resp)
    
    def _init_by_dict(self, chall_dict: Dict[str, str], **kwargs) -> None:
        self.type = ''
        self.url = ''
        self.status = ''
        self.token = ''
        self.validated = ''
        self.error = ''
        self.__dict__.update(chall_dict)
        if 'related_auth' in kwargs:
            self._set_related_auth(kwargs['related_auth'])
    
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
        
        if 'related_auth' in kwargs:
            self._set_related_auth(kwargs['related_auth'])

        self.__dict__.update(self._raw_resp_body)
    
    def _set_related_auth(self, auth_obj: ACMEAuthorization) -> None:
        self._related_auth = auth_obj
    
    @property
    def related_auth(self) -> ACMEAuthorization:
        return self._related_auth