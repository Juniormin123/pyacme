from typing import Dict, Any, List, Tuple, Type, TypeVar, Union
import base64
import json
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

import requests

from pyacme.ACMEobj import ACMEAccount, ACMEChallenge, Empty, ACMEOrder
from pyacme.ACMEobj import ACMEAuthorization
# from pyacme.request import ACMERequestActions, Nonce
from pyacme.exceptions import ACMEError
from pyacme.base import _JWSBase, _JWKBase, _AcctActionBase
from pyacme.util import parse_csr
from pyacme.jws import JWSRS256
from pyacme.jwk import JWKRSA


__all__ = ['ACMEAccountActions', 'RS256Actions']


# TODO proper logging

TJWS = TypeVar('TJWS', bound=Type[_JWSBase])


class ACMEAccountActions(_AcctActionBase):
    """helper class to execute account management actions"""
    
    # def __init__(self, req_action: ACMERequestActions):
    #     self.req_action = req_action
    
    def create_acct(self, 
                    jwk: _JWKBase, 
                    contact: List[str], 
                    # jws_type: TJWS) -> ACMEAccount:
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
        # acct_obj = ACMEAccount(resp)
        # acct_obj.set_jwk(jwk)
        # return acct_obj
        return resp
    
    # def query_acct(self, jwk: _JWKBase, jws_type: TJWS) -> ACMEAccount:
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
        # acct_obj = ACMEAccount(resp)
        # acct_obj.set_jwk(jwk)
        # return acct_obj
        return resp
    
    def update_acct(self, 
                    acct_obj: ACMEAccount,
                    # jwk: _JWKBase,
                    jws_type: TJWS,
                    # **kwargs) -> ACMEAccount:
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
        # # return ACMEAccount(resp)
        # acct_obj.update(resp)
        # return acct_obj
        return resp
    
    def external_acct_binding(self):
        """
        see https://tools.ietf.org/html/rfc8555#section-7.3.4
        """
        pass

    def acct_key_rollover(self, 
                          acct_obj: ACMEAccount,
                          jwk_new: _JWKBase,
                        #   jwk_old: _JWKBase,
                        #   jws_type: TJWS) -> Union[ACMEAccount, Empty]:
                          jws_type: TJWS) -> requests.Response:
        """
        change the public key that is associtated with an account, both new and
        old key should be provided as `jwk` instance.

        see https://tools.ietf.org/html/rfc8555#section-7.3.5
        """
        inner_jws = jws_type(
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
            # payload=outer_payload,
            payload=inner_jws.post_body,
            jwk=acct_obj.jwk_obj,
            kid=acct_obj.acct_location
        )    # type: ignore
        outer_jws.sign()
        resp = self.req_action.key_change(outer_jws)
        if resp.status_code >= 400:
            raise ACMEError(resp)
        return resp

        # acct_obj._set_jwk(jwk_new)
        # if resp.text:
        #     # # return ACMEAccount(resp)
        #     # acct_obj.update(resp)
        #     # return acct_obj
        #     return resp
        # else:
        #     # in pebble always return empty resp body for key-change,
        #     # return Empty(resp)
        #     cls = type(self)
        #     if len(cls.mro()) > 2:
        #         # this means subclass is calling method;
        #         # ensure the parent method will be called
        #         parent_query = super(cls, self)
        #     else:
        #         # if no subclass used
        #         parent_query = self
        #     # query_resp = parent_query.query_acct(jwk_new, jws_type)._resp
        #     # acct_obj.update(query_resp)
        #     # return acct_obj
        #     query_resp = parent_query.query_acct(jwk_new, jws_type)
        #     return query_resp
    
    def deactivate_acct(self, 
                        acct_obj: ACMEAccount, 
                        # jwk: _JWKBase,
                        # jws_type: TJWS) -> ACMEAccount:
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
        # # return ACMEAccount(resp)
        # acct_obj.update(resp)
        # return acct_obj
        return resp


# class ACMECertificateAction:
#     """actions for certificate operation"""

#     def __init__(self, req_action: ACMERequestActions) -> None:
#         self.req_action = req_action
    
    def new_order(self, 
                  acct_obj: ACMEAccount, 
                  identifiers: List[Dict[str, Any]],
                  not_before: str,
                  not_after: str,
                #   jwk: _JWKBase,
                #   jws_type: TJWS) -> ACMEOrder:
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
        # # append order object to an account
        # order = ACMEOrder(resp)
        # acct_obj.set_order(order)
        # return order
        return resp
    
    def post_as_get(self, 
                    url: str,
                    acct_obj: ACMEAccount,
                    # jwk: _JWKBase,
                    # jws_type: TJWS) -> List[ACMEAuthorization]:
                    jws_type: TJWS) -> requests.Response:
        """
        POST-as-GET to a resource's url, payload is empty string `""`; 
         * return `requests.Response`

        see https://tools.ietf.org/html/rfc8555#section-7.5
        """
        # rtn: List[ACMEAuthorization] = []
        # for auth_url in acct_obj.order_obj.authorizations:
        jws = jws_type(
            url=url,
            nonce=str(self.req_action.nonce),
            payload="",
            jwk=acct_obj.jwk_obj,
            kid=acct_obj.acct_location
        )
        jws.sign()
        resp = self.req_action._request(
            # url=auth_url,
            url=url,
            method='post',
            jws=jws
        )
        if resp.status_code >= 400:
            raise ACMEError(resp)
        # rtn.append(ACMEAuthorization(resp, auth_url=auth_url))
        # set account object's authorization attr
        # # acct_obj.set_auth(rtn)
        # return rtn
        return resp
    
    def respond_to_challenge(self, 
                            #  chall_type: str,
                            #  acct_obj: ACMEAccount,
                            #  auth_obj: ACMEAuthorization,
                             chall_obj: ACMEChallenge,
                            #  jwk: _JWKBase,
                            #  jws_type: TJWS) -> ACMEChallenge:
                             jws_type: TJWS) -> requests.Response:
        """
        respond to a challenge url stated in the `challenges` attr in an
        `ACMEAuthorization` instance; payload is empty dict `{}`; expect 200-OK
        if chanllenge object is updated by server.
         * return `requests.Response`

        see https://tools.ietf.org/html/rfc8555#section-7.5.1
        """
        # if not chall_type in ['dns', 'http', 'tls']:
        #     raise ValueError(
        #         f"not recognized challenge type: {chall_type}, " \
        #         f"chall_type must be one of 'dns', 'http', 'tls'"
        #     )
        # _map = {'dns': 'dns-01', 'http': 'http-01', 'tls': 'tls-alpn-01'}
        # rtn: Tuple[str, str]
        # for chall_obj in auth_obj.chall_objs:
        #     # only one chall_obj will be responded to and updated
        #     if chall_obj.type == _map[chall_type]:
        #         # TODO may need to check status
        #         # rtn = (chall_obj.url, chall_obj.token)
        #         url=chall_obj.url
        #         jws = jws_type(
        #             url=url,
        #             nonce=str(self.req_action.nonce),
        #             payload=dict(),
        #             jwk=acct_obj.jwk_obj,
        #             kid=acct_obj.acct_location
        #         )
        #         jws.sign()
        #         resp = self.req_action._request(
        #             url=url,
        #             method='post',
        #             jws=jws
        #         )
        #         if resp.status_code >= 400:
        #             raise ACMEError(resp)
        #         # update chall_obj, this should be updated also in
        #         # the auth_obj.chall_objs by querying identifier_auth() again
        #         chall_obj.update_by_resp(resp)
        #         return chall_obj
        #         # return ACMEChallenge(json.loads(resp.text))
        # else:
        #     raise ValueError(
        #         f'no matching challenge type for {auth_obj.challenges}'
        #     )
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
                        # acct_obj: ACMEAccount, 
                        auth_obj: ACMEAuthorization,
                        # jws_type: TJWS) -> ACMEAuthorization:
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
            # jwk=acct_obj.jwk_obj,
            # kid=acct_obj.acct_location
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
        # auth_obj.update(resp)
        # # update auth obj in acct_obj.auth_objs
        # TODO better solution for updating auth_obj
        # for i, _auth_obj in enumerate(acct_obj.auth_objs):
        #     if auth_obj is _auth_obj:
        #         acct_obj.auth_objs.pop(i)
        #         acct_obj.auth_objs.append(_auth_obj)
        # return auth_obj
        return resp

    def finalize_order(self, 
                    #    acct_obj: ACMEAccount, 
                       order_obj: ACMEOrder,
                       privkey: Union[RSAPrivateKey, str],
                       domains: List[str],
                       subject_names: Dict[str, str],
                    #    engine: str,
                    #    jws_type: TJWS) -> List[ACMEOrder]:
                       jws_type: TJWS) -> requests.Response:
        """
        request to finalize acme order. `ACMEOrder` is tied to one 
        `AMCEAccount`, expect 200-OK if finalize is completed.
         * payload is b64 encoded `CSR`
         * return `requests.Response`

        see https://tools.ietf.org/html/rfc8555#section-7.4 p47
        """
        # rtn: List[ACMEOrder] = []
        # for identifier in acct_obj.order_obj.identifiers:
        csr_der_output = parse_csr(
            # privkey_path=order_obj.related_acct.jwk_obj.priv_key_path,
            privkey=privkey,
            domains=domains,
            # engine=engine,
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
            # rtn.append(ACMEOrder(resp))
        # return rtn
        return resp


class RS256Actions(ACMEAccountActions):

    def create_acct(self, jwk: JWKRSA, contact: List[str]) -> ACMEAccount:
        return super().create_acct(jwk, contact, jws_type=JWSRS256)
    
    def query_acct(self, jwk: JWKRSA) -> ACMEAccount:
        return super().query_acct(jwk, jws_type=JWSRS256)
    
    def update_acct(self, acct_obj: ACMEAccount, **kwargs) -> ACMEAccount:
        return super().update_acct(acct_obj, JWSRS256, **kwargs)
    
    def acct_key_rollover(self, acct_obj: ACMEAccount, 
                          jwk_new: _JWKBase) -> ACMEAccount:
        return super().acct_key_rollover(acct_obj, jwk_new, JWSRS256)
    
    def deactivate_acct(self, acct_obj: ACMEAccount) -> ACMEAccount:
        return super().deactivate_acct(acct_obj, JWSRS256)
    
    def new_order(self, acct_obj: ACMEAccount, 
                  identifiers: List[Dict[str, Any]], not_before: str = '',
                  not_after: str = '') -> ACMEOrder:
        return super().new_order(acct_obj, identifiers, not_before, 
                                 not_after, JWSRS256)
    
    # def identifier_auth(self, acct_obj: ACMEAccount) -> List[ACMEAuthorization]:
    #     return super().post_as_get(acct_obj, JWSRS256)
    
    def respond_to_challenge(self, chall_type: str, acct_obj: ACMEAccount, 
                             auth_obj: ACMEAuthorization) -> ACMEChallenge:
        return super().respond_to_challenge(
            chall_type, acct_obj, auth_obj, JWSRS256
        )
    
    def deactivate_auth(self, acct_obj: ACMEAccount, 
                        auth_obj: ACMEAuthorization) -> ACMEAuthorization:
        return super().deactivate_auth(acct_obj, auth_obj, JWSRS256)