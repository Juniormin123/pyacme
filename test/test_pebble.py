import time

import pytest

from conftest import rsa, Path
from conftest import ACMERequestActions, JWSRS256, JWKRSA, _JWKBase, \
                     ACMEAccount, ACMEAccountActions, ACMEError, ACMEOrder, \
                     settings
from test_common import *


def count_equal(a_list: list, b_list: list) -> None:
    """assert equality of two lists, order not considered"""
    a_list, b_list = sorted(a_list), sorted(b_list)
    assert len(a_list) == len(b_list)
    assert all([a == b for a, b in zip(a_list, b_list)])


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


class TestACMEAccountObjectCreation:

    def test_init_by_create(self, 
                            new_jwk: _JWKBase,
                            new_acct_action: ACMEAccountActions):
        acct_obj = ACMEAccount.init_by_create(
            jwk=new_jwk,
            acct_actions=new_acct_action,
            contact=TEST_CONTACTS
        )
        # reponse 201-created if an account is created
        assert acct_obj._resp.status_code == 201

    def test_init_by_query(self, 
                           new_acct_action: ACMEAccountActions,
                           new_acct_obj: ACMEAccount):
        acct_obj_query = ACMEAccount.init_by_query(
            jwk=new_acct_obj.jwk_obj,
            acct_actions=new_acct_action
        )
        # reponse 200-OK if an account is returned successfully
        assert acct_obj_query._resp.status_code == 200


class TestACMEAccountActions:

    def test_poll_acct_state(self, new_acct_obj: ACMEAccount):
        # for an acct just created, status code will be 201
        assert new_acct_obj._resp.status_code == 201
        new_acct_obj.poll_acct_state()
        # poll and update acct state, status code will be updated to 200
        assert new_acct_obj._resp.status_code == 200
    
    def test_update_account(self, new_acct_obj: ACMEAccount):
        new_acct_obj.update_account(contact=TEST_CONTACTS_MOD)
        # successful update will return 200-OK
        assert new_acct_obj._resp.status_code == 200
        new_acct_obj.poll_acct_state()
        # assert if attribute "contact" is actually updated
        count_equal(new_acct_obj.contact, TEST_CONTACTS_MOD)
    
    def test_deactivate(self, new_acct_obj: ACMEAccount):
        new_acct_obj.deactivate()
        # successful deactivation will return 200-OK
        assert new_acct_obj._resp.status_code == 200
        assert new_acct_obj.status == 'deactivated'
        # now post-as-get to a deactivated acct will have 403-Forbidden
        with pytest.raises(ACMEError) as caught:
            new_acct_obj.poll_acct_state()
        assert caught.value.status_code == 403
    
    def test_account_key_rollover(self, 
                                  new_jwk_i: _JWKBase,
                                  new_acct_obj: ACMEAccount):
        new_acct_obj.account_key_rollover(new_jwk_i)
        # successful rollover will return 200-OK
        assert new_acct_obj._resp.status_code == 200
        assert new_acct_obj.jwk_obj is new_jwk_i
        with pytest.raises(ACMEError) as caught:
            new_acct_obj.account_key_rollover(new_jwk_i)
        assert "New and old key are identical" in str(caught.value)


class TestACMEOrder:

    domain = ['i.test.local']
    domains = ['a.test.local', 'b.test.local']

    def _test_new_order_domain(self, d: list, new_acct_obj: ACMEAccount):
        order_obj = new_acct_obj.new_order(identifiers=d)
        # successful order creation will return 201-created
        assert new_acct_obj._resp.status_code == 201
        assert order_obj._resp.status_code == 201
        # only one order related to the account
        assert len(new_acct_obj.order_objs) == 1
        assert new_acct_obj.order_objs[0] is order_obj
        count_equal(d, order_obj.identifier_values)
    
    def test_new_order_single_domain(self, new_acct_obj: ACMEAccount):
        self._test_new_order_domain(self.domain, new_acct_obj)

    def test_new_order_multi_domain(self, new_acct_obj: ACMEAccount):
        self._test_new_order_domain(self.domains, new_acct_obj)
    
    def test_poll_order_state(self, new_order_obj: ACMEOrder):
        new_order_obj.poll_order_state()
        assert new_order_obj._resp.status_code == 200
    
    def test_get_orders(self, 
                        new_acct_action: ACMEAccountActions,
                        new_acct_obj: ACMEAccount,
                        new_order_obj: ACMEOrder):
        assert len(new_acct_obj.order_objs) == 1
        # create new orders directly from account actions
        new_acct_action.new_order(
            acct_obj=new_acct_obj,
            identifiers=[dict(type='dns', value=v) for v in self.domains],
            not_before='',
            not_after='',
            jws_type=new_acct_obj.jwk_obj.related_JWS
        )
        # refresh account order list
        new_acct_obj.get_orders()
        assert len(new_acct_obj.order_objs) == 2


class TestACMEAuthorization:

    domain = ['a.test.local', 'b.test.local']

    def test_poll_auth_state(self, new_order_obj: ACMEOrder):
        assert len(new_order_obj.auth_objs) == 2
        for auth in new_order_obj.auth_objs:
            auth.poll_auth_state()
            assert auth._resp.status_code == 200
    
    def test_deactivate_auth(self, new_order_obj: ACMEOrder):
        auth_to_deactivate = new_order_obj.auth_objs[0]
        auth_to_deactivate.deactivate_auth()
        # successful deactivation will return 200-OK
        assert auth_to_deactivate._resp.status_code == 200
        assert auth_to_deactivate.status == 'deactivated'
        # related order state will also become "deactivated"
        new_order_obj.poll_order_state()
        assert new_order_obj.status == 'deactivated'


class TestACMEChallenge:
    """respond using pebble challtest"""

    # use one order with 1 auth to save test time
    domain = ['a.test.local']

    def test_respond_http(self, new_order_obj: ACMEOrder):
        jwk = new_order_obj.related_acct.jwk_obj
        for auth in new_order_obj.auth_objs:
            add_http_01(auth.chall_http.token, jwk)
            auth.chall_http.respond()
            # if poll auth immediately after repond, status should be "pending"
            auth.poll_auth_state()
            assert auth.status == 'pending'
            time.sleep(4)
            auth.poll_auth_state()
            assert auth.chall_http.status == 'valid'
            assert auth.status == 'valid'
        # once all auth valid, order state become "ready"
        new_order_obj.poll_order_state()
        assert new_order_obj.status == 'ready'

    @staticmethod
    def _test_respond_dns(new_order_obj: ACMEOrder):
        jwk = new_order_obj.related_acct.jwk_obj
        for auth in new_order_obj.auth_objs:
            add_dns_01(auth.chall_dns.token, auth.identifier_value, jwk)
            auth.chall_dns.respond()
            # if poll auth immediately after repond, status should be "pending"
            auth.poll_auth_state()
            assert auth.status == 'pending'
            time.sleep(5)
            auth.poll_auth_state()
            assert auth.chall_dns.status == 'valid'
            assert auth.status == 'valid'
        # once all auth valid, order state become "ready"
        new_order_obj.poll_order_state()
        assert new_order_obj.status == 'ready'
    
    def test_respond_dns(self, new_order_obj: ACMEOrder):
        self._test_respond_dns(new_order_obj)
    
    @pytest.mark.domain('*.test.local')
    def test_respond_dns_wildcard(self, new_order_obj: ACMEOrder):
        print(new_order_obj.identifier_values)
        self._test_respond_dns(new_order_obj)


class TestACMEOrderCertificate:

    domain = ['a.test.local']

    def test_download_cert(self, 
                           new_tmp_wd: Tuple[Path, Path, Path, Path], 
                           new_rsa_privkey_i: rsa.RSAPrivateKey,
                           new_ready_order: ACMEOrder):
        new_ready_order.poll_order_state()
        assert new_ready_order.status == 'ready'
        wd, cert_path, chain_path, fullchain_path = new_tmp_wd
        download_root_cert(wd)
        # test finalize order
        new_ready_order.finalize_order(
            privkey=new_rsa_privkey_i,
            emailAddress='email@address.test',
            C='CN',
            ST='test ST',
            L='test L',
            O='test org',
            OU='test OU'
        )
        time.sleep(1)
        new_ready_order.poll_order_state()
        # after finalized, state become "valid", cannot be finalized again
        assert new_ready_order.status == 'valid'

        # test download cert
        download_resp = new_ready_order.download_certificate(str(wd))
        assert download_resp.status_code == 200

        # external openssl verify
        completed_p = openssl_verify(cert_path, chain_path, wd)
        assert completed_p.returncode == 0