from typing import Dict, Any, List, Tuple, Type, TypeVar, Union
import base64
import json
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

import requests

from pyacme.ACMEobj import ACMEAccount, ACMEChallenge, Empty, ACMEOrder
from pyacme.ACMEobj import ACMEAuthorization
from pyacme.exceptions import ACMEError
from pyacme.base import _JWSBase, _JWKBase, _AcctActionBase
from pyacme.util import parse_csr
from pyacme.jws import JWSRS256
from pyacme.jwk import JWKRSA


# TODO cancel param jws_type


__all__ = ['ACMEAccountActions', 'RS256Actions']


TJWS = TypeVar('TJWS', bound=Type[_JWSBase])


class ACMEAccountActions(_AcctActionBase):
    """helper class to execute account management actions"""
    
    def create_acct(self, 
                    jwk: _JWKBase, 
                    contact: List[str], 
                    jws_type: TJWS) -> requests.Response:
        """
        create acme account using a pub key, contact should
        be a list of "mailto:" address; upon success return
        201-created; if account exist, return 200-OK
        """
        jws = jws_type(
            url=self.req_action.acme_dir['newAccount'],
            nonce=str(self.req_action.nonce),
            jwk=jwk,
            payload={
                'termsOfServiceAgreed': True,
                'contact': contact
            }
        )    # type: ignore
        jws.sign()
        resp = self.req_action.new_account(jws)
        if resp.status_code >= 400:
            raise(ACMEError(resp))
        return resp
    
    def query_acct(self, jwk: _JWKBase, jws_type: TJWS) -> requests.Response:
        """
        query if an account is recorded by server, will not 
        create new account; upon success return 200-OK
        
        see https://tools.ietf.org/html/rfc8555#section-7.3.1
        """
        jws = jws_type(
            url=self.req_action.acme_dir['newAccount'],
            nonce=str(self.req_action.nonce),
            jwk=jwk,
            payload={
                'onlyReturnExisting': True
            }
        )    # type: ignore
        jws.sign()
        resp = self.req_action.new_account(jws)
        if resp.status_code >= 400:
            raise(ACMEError(resp))
        return resp
    
    def update_acct(self, 
                    acct_obj: ACMEAccount,
                    jws_type: TJWS,
                    **kwargs) -> requests.Response:
        """
        send updated payload to an account url, update on 
        `termsOfServiceAgreed`, `orders` and `status` will be ignored; 
        `contact` is the usual update target

        see https://tools.ietf.org/html/rfc8555#section-7.3.2
        """
        jws = jws_type(
            url=acct_obj.acct_location,
            nonce=str(self.req_action.nonce),
            payload=kwargs,
            jwk=acct_obj.jwk_obj,
            kid=acct_obj.acct_location
        )    # type: ignore
        jws.sign()
        resp = self.req_action._request(
            url=acct_obj.acct_location,
            method='post',
            jws=jws
        )
        if resp.status_code >= 400:
            raise(ACMEError(resp))
        return resp
    
    def external_acct_binding(self):
        """
        see https://tools.ietf.org/html/rfc8555#section-7.3.4
        """
        pass

    def acct_key_rollover(self, 
                          acct_obj: ACMEAccount,
                          jwk_new: _JWKBase,
                          jws_type: TJWS) -> requests.Response:
        """
        change the public key that is associtated with an account, both new and
        old key should be provided as `jwk` instance.

        see https://tools.ietf.org/html/rfc8555#section-7.3.5
        """
        inner_jws = jwk_new.related_JWS(
            url=self.req_action.acme_dir['keyChange'],
            # nonce ignored in inner jws
            nonce='',
            # inner payload is a "keyChange" object, see rfc8555 page 41
            payload={
                'account': acct_obj.acct_location,
                'oldKey': acct_obj.jwk_obj._container
            },
            jwk=jwk_new
        )    # type: ignore
        inner_jws.protected.pop('nonce')
        inner_jws.sign()

        outer_jws = jws_type(
            url=self.req_action.acme_dir['keyChange'],
            nonce=str(self.req_action.nonce),
            payload=inner_jws.post_body,
            jwk=acct_obj.jwk_obj,
            kid=acct_obj.acct_location
        )    # type: ignore
        outer_jws.sign()
        resp = self.req_action.key_change(outer_jws)
        if resp.status_code >= 400:
            raise ACMEError(resp)
        return resp
    
    def deactivate_acct(self, 
                        acct_obj: ACMEAccount, 
                        jws_type: TJWS) -> requests.Response:
        """
        deactivate an account, issued certificate will not be revoked.
        
        see https://tools.ietf.org/html/rfc8555#section-7.3.6
        """
        jws = jws_type(
            url=acct_obj.acct_location,
            nonce=str(self.req_action.nonce),
            payload={'status': 'deactivated'},
            jwk=acct_obj.jwk_obj,
            kid=acct_obj.acct_location
        )    # type: ignore
        jws.sign()
        resp = self.req_action._request(
            url=acct_obj.acct_location,
            method='post',
            jws=jws
        )
        if resp.status_code >= 400:
            raise(ACMEError(resp))
        return resp
    
    def new_order(self, 
                  acct_obj: ACMEAccount, 
                  identifiers: List[Dict[str, Any]],
                  not_before: str,
                  not_after: str,
                  jws_type: TJWS) -> requests.Response:
        """
        request for new order, expect 201-created upon success. 

         * `identifiers`: e.g. `[{'type': 'dns', 'value': 'test.org'}, ...]` 
         * `not_before`, `not_after`: both optional, datetime string specified 
         in https://tools.ietf.org/html/rfc3339, can be empty `''`
         * return an `requests.Response`;

        see https://tools.ietf.org/html/rfc8555#section-7.4, page 45-46
        """
        payload = {'identifiers': identifiers}
        if not_before:
            payload['notBefore'] = not_before
        if not_after:
            payload['notAfter'] = not_after
        
        jws = jws_type(
            url=self.req_action.acme_dir['newOrder'],
            nonce=str(self.req_action.nonce),
            payload=payload,
            jwk=acct_obj.jwk_obj,
            kid=acct_obj.acct_location
        )
        jws.sign()
        resp = self.req_action.new_order(jws)
        if resp.status_code >= 400:
            raise ACMEError(resp)
        return resp
    
    def post_as_get(self, 
                    url: str,
                    acct_obj: ACMEAccount,
                    jws_type: TJWS) -> requests.Response:
        """
        POST-as-GET to a resource's url, payload is empty string `""`; 
         * return `requests.Response`

        see https://tools.ietf.org/html/rfc8555#section-7.5
        """
        jws = jws_type(
            url=url,
            nonce=str(self.req_action.nonce),
            payload="",
            jwk=acct_obj.jwk_obj,
            kid=acct_obj.acct_location
        )
        jws.sign()
        resp = self.req_action._request(
            url=url,
            method='post',
            jws=jws
        )
        if resp.status_code >= 400:
            raise ACMEError(resp)
        return resp
    
    def respond_to_challenge(self, 
                             chall_obj: ACMEChallenge,
                             jws_type: TJWS) -> requests.Response:
        """
        respond to a challenge url stated in the `challenges` attr in an
        `ACMEAuthorization` instance; payload is empty dict `{}`; expect 200-OK
        if chanllenge object is updated by server.
         * return `requests.Response`

        see https://tools.ietf.org/html/rfc8555#section-7.5.1
        """
        jws = jws_type(
            # the "url" attr of chall_obj, not the location of the obj
            url=chall_obj.url,
            nonce=str(self.req_action.nonce),
            payload=dict(),
            jwk=chall_obj.related_auth.related_order.related_acct.jwk_obj,
            kid=chall_obj.related_auth.related_order.related_acct.acct_location
        )
        jws.sign()
        resp = self.req_action._request(
            url=chall_obj.url,
            method='post',
            jws=jws
        )
        if resp.status_code >= 400:
            raise ACMEError(resp)
        return resp
    
    def deactivate_auth(self, 
                        auth_obj: ACMEAuthorization,
                        jws_type: TJWS) -> requests.Response:
        """
        request to deactivate an authorization; `auth_obj` should be one of the
        element from `acct_obj.auth_objs`; accot_obj will be updated
         * payload `{"status": "deactivated"}`
         * return `requests.Response`

        see https://tools.ietf.org/html/rfc8555#section-7.5.2
        """
        jws = jws_type(
            url=auth_obj.auth_location,
            nonce=str(self.req_action.nonce),
            payload={'status': 'deactivated'},
            jwk=auth_obj.related_order.related_acct.jwk_obj,
            kid=auth_obj.related_order.related_acct.acct_location
        )
        jws.sign()
        resp = self.req_action._request(
            url=auth_obj.auth_location,
            method='post',
            jws=jws
        )
        if resp.status_code >= 400:
            raise ACMEError(resp)
        return resp

    def finalize_order(self, 
                       order_obj: ACMEOrder,
                       privkey: Union[RSAPrivateKey, str],
                       domains: List[str],
                       subject_names: Dict[str, str],
                       jws_type: TJWS) -> requests.Response:
        """
        request to finalize acme order. `ACMEOrder` is tied to one 
        `AMCEAccount`, expect 200-OK if finalize is completed.
         * payload is b64 encoded `CSR`
         * return `requests.Response`

        see https://tools.ietf.org/html/rfc8555#section-7.4 p47
        """
        csr_der_output = parse_csr(
            privkey=privkey,
            domains=domains,
            **subject_names
        )
        csr_der_b = base64.urlsafe_b64encode(csr_der_output).strip(b'=')
        jws = jws_type(
            url=order_obj.finalize,
            nonce=str(self.req_action.nonce),
            payload={
                'csr': csr_der_b.decode('utf-8'),
            },
            jwk=order_obj.related_acct.jwk_obj,
            kid=order_obj.related_acct.acct_location
        )
        jws.sign()
        resp = self.req_action._request(
            url=order_obj.finalize,
            method='post',
            jws=jws
        )
        if resp.status_code >= 400:
            raise ACMEError(resp)
        return resp
