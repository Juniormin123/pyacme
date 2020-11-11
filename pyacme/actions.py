from typing import Dict, Any, List

from pyacme.ACMEobj import ACMEAccount
from pyacme.requests import ACMERequestActions
from pyacme.jws import JWSRS256
from pyacme.jwk import JWKRSA

# proper logging


class ACMEAccountActions:
    """helper class to execute account management actions"""
    
    def __init__(self, req_action: ACMERequestActions):
        self.req_action = req_action
    
    def create_acct_RS256(self, jwk: JWKRSA, contact: List[str]):
        """
        create acme account using RSA pub key, contact should
        be a list of "mailto:" address; upon success return
        201-created; if account exist, return 200-OK
        """
        jws = JWSRS256(
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
    
    def query_acct_RS256(self, jwk: JWKRSA):
        """
        query if an account is recorded by server, will not 
        create new account; upon success return 200-OK
        
        see https://tools.ietf.org/html/rfc8555#section-7.3.1
        """
        jws = JWSRS256(
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