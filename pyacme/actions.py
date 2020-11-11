from typing import Dict, Any, List, Type

from pyacme.ACMEobj import ACMEAccount
from pyacme.requests import ACMERequestActions
from pyacme.base import _JWSBase, _JWKBase
from pyacme.jws import JWSRS256
from pyacme.jwk import JWKRSA

# proper logging


class ACMEAccountActions:
    """helper class to execute account management actions"""
    
    def __init__(self, req_action: ACMERequestActions):
        self.req_action = req_action
    
    def create_acct(self, 
                    jwk: _JWKBase, 
                    contact: List[str], 
                    jws_type: Type[_JWSBase]) -> ACMEAccount:
        """
        create acme account using RSA pub key, contact should
        be a list of "mailto:" address; upon success return
        201-created; if account exist, return 200-OK
        """
        jws = jws_type(    # type: ignore
            url=self.req_action.acme_dir['newAccount'],
            nonce=str(self.req_action.nonce),
            jwk=jwk,
            payload={
                'termsOfServiceAgreed': True,
                'contact': contact
            }
        )
        jws.sign()
        resp = self.req_action.new_account(jws)
        return ACMEAccount(resp)
    
    def query_acct(self, 
                   jwk: _JWKBase, 
                   jws_type: Type[_JWSBase]) -> ACMEAccount:
        """
        query if an account is recorded by server, will not 
        create new account; upon success return 200-OK
        
        see https://tools.ietf.org/html/rfc8555#section-7.3.1
        """
        jws = jws_type(    # type: ignore
            url=self.req_action.acme_dir['newAccount'],
            nonce=str(self.req_action.nonce),
            jwk=jwk,
            payload={
                'onlyReturnExisting': True
            }
        )
        jws.sign()
        resp = self.req_action.new_account(jws)
        return ACMEAccount(resp)


class RS256AccountActions(ACMEAccountActions):

    def create_acct(self, jwk: JWKRSA, contact: List[str]) -> ACMEAccount:
        return super().create_acct(jwk, contact, jws_type=JWSRS256)
    
    def query_acct(self, jwk: JWKRSA) -> ACMEAccount:
        return super().query_acct(jwk, JWSRS256)