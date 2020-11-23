# type: ignore[override]
from email.message import EmailMessage
from os import kill
from typing import Dict, Any, List, Tuple, Type, TypeVar, Union
import base64
import json

from pyacme.ACMEobj import ACMEAccount, ACMEChallenge, Empty, ACMEOrder, ACMEAuthorization
from pyacme.requests import ACMERequestActions, Nonce
from pyacme.exceptions import ACMEError
from pyacme.base import _JWSBase, _JWKBase
from pyacme.jws import JWSRS256
from pyacme.jwk import JWKRSA


# TODO proper logging

TJWS = TypeVar('TJWS', bound=Type[_JWSBase])


class ACMEAccountActions:
    """helper class to execute account management actions"""
    
    def __init__(self, req_action: ACMERequestActions):
        self.req_action = req_action
    
    def create_acct(self, 
                    jwk: _JWKBase, 
                    contact: List[str], 
                    jws_type: TJWS) -> ACMEAccount:
        """
        create acme account using RSA pub key, contact should
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
        return ACMEAccount(resp)
    
    def query_acct(self, jwk: _JWKBase, jws_type: TJWS) -> ACMEAccount:
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
        return ACMEAccount(resp)
    
    def update_acct(self, 
                    acct_obj: ACMEAccount,
                    jwk: _JWKBase,
                    jws_type: TJWS,
                    **kwargs) -> ACMEAccount:
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
            jwk=jwk,
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
        return ACMEAccount(resp)
    
    def external_acct_binding(self):
        """
        see https://tools.ietf.org/html/rfc8555#section-7.3.4
        """
        return NotImplemented

    def acct_key_rollover(self, 
                          acct_obj: ACMEAccount,
                          jwk_new: _JWKBase,
                          jwk_old: _JWKBase,
                          jws_type: TJWS) -> Union[ACMEAccount, Empty]:
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
                'oldKey': jwk_old._container
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
            jwk=jwk_old,
            kid=acct_obj.acct_location
        )    # type: ignore
        outer_jws.sign()
        resp = self.req_action.key_change(outer_jws)
        if resp.status_code >= 400:
            raise(ACMEError(resp))
        if resp.text:
            return ACMEAccount(resp)
        else:
            # in pebble always return empty resp body for key-change
            return Empty(resp)
    
    def deactivate_acct(self, 
                        acct_obj: ACMEAccount, 
                        jwk: _JWKBase,
                        jws_type: TJWS) -> ACMEAccount:
        """
        deactivate an account, issued certificate will not be revoked.
        
        see https://tools.ietf.org/html/rfc8555#section-7.3.6
        """
        jws = jws_type(
            url=acct_obj.acct_location,
            nonce=str(self.req_action.nonce),
            payload={'status': 'deactivated'},
            jwk=jwk,
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
        return ACMEAccount(resp)


class ACMECertificateAction:
    """actions for certificate operation"""

    def __init__(self, req_action: ACMERequestActions) -> None:
        self.req_action = req_action
    
    def new_order(self, 
                  acct_obj: ACMEAccount, 
                  identifiers: List[Dict[str, Any]],
                  not_before: str,
                  not_after: str,
                  jwk: _JWKBase,
                  jws_type: TJWS) -> ACMEOrder:
        """
        request for new order, expect 201-created upon success. 

         * `identifiers`: e.g. `[{'type': 'dns', 'value': 'test.org'}, ...]` 
         * `not_before`, `not_after`: both optional, datetime string specified 
         in https://tools.ietf.org/html/rfc3339, can be empty `''`
         * return an `ACMEOrder` object;

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
            jwk=jwk,
            kid=acct_obj.acct_location
        )
        jws.sign()
        resp = self.req_action.new_order(jws)
        if resp.status_code >= 400:
            raise ACMEError(resp)
        # append order object to an account
        order = ACMEOrder(resp)
        acct_obj.set_order(order)
        return order
    
    def identifier_auth(self, 
                        acct_obj: ACMEAccount,
                        jwk: _JWKBase,
                        jws_type: TJWS) -> List[ACMEAuthorization]:
        """
        POST-as-GET to urls in `ACMEOrder.authorizations` to query an auth, 
        payload is empty string `""`; 
         * return `ACMEAuthorization`

        see https://tools.ietf.org/html/rfc8555#section-7.5
        """
        rtn: List[ACMEAuthorization] = []
        for auth_url in acct_obj.order.authorizations:
            jws = jws_type(
                url=auth_url,
                nonce=str(self.req_action.nonce),
                payload="",
                jwk=jwk,
                kid=acct_obj.acct_location
            )
            jws.sign()
            resp = self.req_action._request(
                url=auth_url,
                method='post',
                jws=jws
            )
            if resp.status_code >= 400:
                raise ACMEError(resp)
            rtn.append(ACMEAuthorization(resp))
        return rtn
    
    def respond_to_challenge(self, 
                             chall_type: str,
                             acct_obj: ACMEAccount,
                             auth_obj: ACMEAuthorization,
                             jwk: _JWKBase,
                             jws_type: TJWS) -> ACMEAuthorization:
        """
        responde to a challenge url stated in the `challenges` attr in an
        `ACMEAuthorization` instance; payload is empty dict `{}`; expect 200-OK
        if chanllenge object is updated by server.
         * return `ACMEAuthorization`

        see https://tools.ietf.org/html/rfc8555#section-7.5.1
        """
        if not chall_type in ['dns', 'http', 'tls']:
            raise ValueError(
                f"not recognized challenge type: {chall_type}, " \
                f"chall_type must be one of 'dns', 'http', 'tls'"
            )
        _map = {'dns': 'dns-01', 'http': 'http-01', 'tls': 'tls-alpn-01'}
        rtn: Tuple[str, str]
        for chall_obj in auth_obj.challenges:
            if chall_obj.type == _map[chall_type]:
                # TODO may need to check status
                # rtn = (chall_obj.url, chall_obj.token)
                url=chall_obj.url
                break
        else:
            raise ValueError(
                f'no matching challenge type for {auth_obj.challenges}'
            )
        jws = jws_type(
            url=url,
            nonce=str(self.req_action.nonce),
            payload=dict(),
            jwk=jwk,
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
        return ACMEChallenge(json.loads(resp.text))


class RS256Actions(ACMEAccountActions, ACMECertificateAction):

    def create_acct(self, jwk: JWKRSA, contact: List[str]) -> ACMEAccount:
        return super().create_acct(jwk, contact, jws_type=JWSRS256)
    
    def query_acct(self, jwk: JWKRSA) -> ACMEAccount:
        return super().query_acct(jwk, jws_type=JWSRS256)
    
    def update_acct(self, acct_obj: ACMEAccount, 
                    jwk: _JWKBase, **kwargs) -> ACMEAccount:
        return super().update_acct(acct_obj, jwk, JWSRS256, **kwargs)
    
    def acct_key_rollover(self, acct_obj: ACMEAccount, jwk_new: _JWKBase, 
                          jwk_old: _JWKBase) -> ACMEAccount:
        return super().acct_key_rollover(acct_obj, jwk_new, jwk_old, JWSRS256)
    
    def deactivate_acct(self, acct_obj: ACMEAccount, 
                        jwk: _JWKBase) -> ACMEAccount:
        return super().deactivate_acct(acct_obj, jwk, JWSRS256)
    
    def new_order(self, acct_obj: ACMEAccount, jwk: JWKRSA,
                  identifiers: List[Dict[str, Any]], not_before: str = '',
                  not_after: str = '') -> ACMEOrder:
        return super().new_order(acct_obj, identifiers, not_before, 
                                 not_after, jwk, JWSRS256)
    
    def identifier_auth(self, acct_obj: ACMEAccount, 
                        jwk: _JWKBase) -> List[ACMEAuthorization]:
        return super().identifier_auth(acct_obj, jwk, JWSRS256)
    
    def respond_to_challenge(self, chall_type: str, acct_obj: ACMEAccount, 
                             auth_obj: ACMEAuthorization, jwk: _JWKBase, 
                             jws_type: TJWS) -> ACMEAuthorization:
        return super().respond_to_challenge(
            chall_type, acct_obj, auth_obj, jwk, JWSRS256
        )