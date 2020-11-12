from typing import Dict, Any, List, Type, TypeVar

from pyacme.ACMEobj import ACMEAccount
from pyacme.requests import ACMERequestActions
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
            jwk=jwk,
            payload=kwargs,
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


class RS256AccountActions(ACMEAccountActions):

    def create_acct(self, jwk: JWKRSA, contact: List[str]) -> ACMEAccount:
        return super().create_acct(jwk, contact, jws_type=JWSRS256)
    
    def query_acct(self, jwk: JWKRSA) -> ACMEAccount:
        return super().query_acct(jwk, jws_type=JWSRS256)
    
    def update_acct(self, acct_obj: ACMEAccount, 
                    jwk: _JWKBase, **kwargs) -> ACMEAccount:
        return super().update_acct(acct_obj, jwk, JWSRS256, **kwargs)