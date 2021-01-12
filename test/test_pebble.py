import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from conftest import ACMERequestActions, JWSRS256, JWKRSA, _JWKBase
from test_common import *


class TestACMERequestActionsTest:

    def test_retry_badNonce(self,
                            new_request_action: ACMERequestActions,
                            new_rsa_privkey: rsa.RSAPrivateKey):
        """
        create account without using ACMEAccountAction, while using incorrect
        nonce to trigger badNonce retry.
        """
        req = new_request_action
        jws = JWSRS256(
            url=req.acme_dir['newAccount'],
            nonce='badNonce',
            jwk = JWKRSA(
                priv_key=new_rsa_privkey,
                n=new_rsa_privkey.public_key().public_numbers().n,
                e=new_rsa_privkey.public_key().public_numbers().e
            ),
            payload={
                'termsOfServiceAgreed': True,
                'contact': TEST_CONTACTS
            },
        )
        jws.sign()
        resp = req.new_account(jws)
        assert resp.status_code == 201