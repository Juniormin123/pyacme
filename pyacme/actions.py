# type: ignore[override]
from os import kill
from typing import Dict, Any, List, Type, TypeVar
import base64
import json

from pyacme.ACMEobj import ACMEAccount
from pyacme.requests import ACMERequestActions, Nonce
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
                          jws_type: TJWS) -> ACMEAccount:
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

        # outer_payload = str(
        #     base64.urlsafe_b64encode(
        #         bytes(json.dumps(inner_jws.post_body), encoding='utf-8')
        #     ).strip(b'='),
        #     encoding='utf-8'
        # )
        outer_jws = jws_type(
            url=self.req_action.acme_dir['keyChange'],
            nonce=str(self.req_action.nonce),
            # payload=outer_payload,
            payload=inner_jws.post_body,
            jwk=jwk_old,
            kid=acct_obj.acct_location
        )    # type: ignore
        outer_jws.sign()
        return ACMEAccount(self.req_action.key_change(outer_jws))
    
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
        return ACMEAccount(resp)


class RS256AccountActions(ACMEAccountActions):

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