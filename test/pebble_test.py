"""
run pebble docker:
 * use `docker-compose` 
 * https://github.com/letsencrypt/pebble/blob/master/docker-compose.yml
test using pebble-challtestsrv: 
 * add a dns A/AAAA record in pebble-challtestsrv, `PEBBLE_CHALLTEST_DNS_A`
 * generate challenge content and add to related interface of challtestsrv
 * delete above contents upon test done or exceptions

see https://github.com/letsencrypt/pebble/blob/master/cmd/pebble-challtestsrv/README.md
"""

from typing import Any, Dict, List, Optional, Tuple
from pathlib import Path
import time
import json
import subprocess
import unittest

import requests
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# for running this file directly
import sys
sys.path.append(str(Path(__file__).parents[1].absolute()))

from pyacme.base import _JWKBase, _JWSBase
from pyacme.util import get_keyAuthorization
from pyacme.jwk import JWKRSA
from pyacme.jws import JWSRS256
from pyacme.exceptions import ACMEError
from pyacme.actions import ACMEAccountActions
from pyacme.ACMEobj import ACMEAccount, ACMEAuthorization, ACMEOrder
from pyacme.request import ACMERequestActions, Nonce
from pyacme.settings import *


# test constants
_BASE = Path(__file__).parents[1].absolute()
_RSA_PUB_1 = _BASE / 'test' / 'test_pubkey.pem'
_RSA_PRIV_1 = _BASE / 'test' / 'test_privkey.pem'
_RSA_PUB_2 = _BASE / 'test' / 'test_pubkey_2.pem'
_RSA_PRIV_2 = _BASE / 'test' / 'test_privkey_2.pem'

_TEST_CONTACTS = ['mailto:min641366609@live.com']
_TEST_CONTACTS_MOD = ['mailto:calvin.cheng@synergyfutures.com']

_SLEEP_AFTER_DOCKER = 4

# print(RSA_PUB_1)

global_docker_is_running = False


def _run_cmd(*cmd_args: str) -> None:
    completed = subprocess.run(
        args=cmd_args,
        capture_output=True,
        encoding='utf-8',
        # should raise exception if docker failed to run
        check=True
    )
    # if completed.stdout:
    #     print(completed.stdout)
    # # docker output seems to be on stderr
    # print(completed.stderr)


def run_pebble_docker(docker_file_path: str) -> None:
    """run `docker-compose up` on given docker-compose.yml in the background"""
    global global_docker_is_running
    _run_cmd('docker-compose', '-f', docker_file_path, 'up', '-d')
    # wait for a while to make sure container is up and running
    time.sleep(_SLEEP_AFTER_DOCKER)
    print('docker container running')
    global_docker_is_running = True


def stop_pebble_docker(*docker_names: str) -> None:
    global global_docker_is_running
    """`docker stop DOCKER_NAMES ...`"""
    _run_cmd('docker', 'stop', *docker_names)
    print('docker container stopped')
    global_docker_is_running = False


def restart_pebble_docker(docker_file_path: str, *docker_names: str) -> None:
    stop_pebble_docker(*docker_names)
    run_pebble_docker(docker_file_path)


def restart_pebble_docker_specific():
    if global_docker_is_running:
        restart_pebble_docker(
            PEBBLE_DOCKER_FILE, 
            PEBBLE_CONTAINER, 
            PEBBLE_CHALLTEST_CONTAINER
        )


def add_dns_A(host: str, addr: str) -> requests.Response:
    """add an A record to pebble-challtestsrv"""
    data = json.dumps({'host': host, 'address': addr})
    resp = requests.post(PEBBLE_CHALLTEST_DNS_A, data=data)
    return resp


def add_http_01(token: str, jwk: _JWKBase) -> requests.Response:
    """
    add repsond to challtestsrv, pebble will send challenge request to 
    challtestsrv if pebble recieve `respond_to_challenge` request
    """
    content = get_keyAuthorization(token, jwk)
    resp = requests.post(
        url=PEBBLE_CHALLTEST_HTTP01,
        data=json.dumps({'token': token, 'content': content})
    )
    return resp


def load_test_keys(*key_pair_path: str) -> List[tuple]:
    key_pairs: List[tuple] = []
    for pub_path, priv_path in key_pair_path:
        with open(pub_path, 'rb') as pub_f:
            pub_key = serialization.load_pem_public_key(
                pub_f.read(),
                backend=default_backend()
            )
        with open(priv_path, 'rb') as priv_f:
            priv_key = serialization.load_pem_private_key(
                priv_f.read(),
                password=None,
                backend=default_backend()
            )
        key_pairs.append(((pub_key, priv_key), priv_path))
    return key_pairs


# set up RSA variables
def _set_up_rsa(self):
    self.rsa_test = dict()
    self.rsa_test['key_pair'] = load_test_keys(
        (_RSA_PUB_1, _RSA_PRIV_1),
        (_RSA_PUB_2, _RSA_PRIV_2)
    )
    self.rsa_test['jwk_rsa_list'] = []
    for key_pair, priv_key_path in self.rsa_test['key_pair']:
        jwk_rsa = JWKRSA(
            priv_key=key_pair[1],
            n=key_pair[0].public_numbers().n,
            e=key_pair[0].public_numbers().e,
            priv_key_path=priv_key_path
        )
        self.rsa_test['jwk_rsa_list'].append(jwk_rsa)


class ACMERequestActionsTest(unittest.TestCase):

    def setUp(self) -> None:
        run_pebble_docker(str(PEBBLE_DOCKER_FILE))

        _set_up_rsa(self)

        self.jws_types = [JWSRS256]
        self.jwk_list = [self.rsa_test['jwk_rsa_list']]    # type: ignore

        ACMERequestActions.set_directory_url(PEBBLE_TEST)
        ACMERequestActions.query_dir()

        self.req_action = ACMERequestActions()
    
    def test_retry_badNonce(self):
        self.req_action.new_nonce()
        for jws_type, jwk_list in zip(self.jws_types, self.jwk_list):
            with self.subTest(jws_type=jws_type, jwk=jwk_list):
                # create jws
                jws = jws_type(
                    url=self.req_action.acme_dir['newAccount'],
                    # use a broken nonce, should be able to retry
                    nonce='badNonce',
                    jwk=jwk_list[0],
                    payload={
                        'termsOfServiceAgreed': True,
                        'contact': _TEST_CONTACTS
                    },
                )
                jws.sign()
                resp = self.req_action.new_account(jws)

                # test output
                if resp.status_code >= 400:
                    print(ACMEError(resp))

                # check status code, expect 201-created
                self.assertEqual(resp.status_code, 201)
    
    def tearDown(self) -> None:
        stop_pebble_docker(PEBBLE_CONTAINER, PEBBLE_CHALLTEST_CONTAINER)


def common_setup(self, create_account = True):
    run_pebble_docker(str(PEBBLE_DOCKER_FILE))
    
    _set_up_rsa(self)
    self.jws_types = [JWSRS256]
    self.jwk_list = self.rsa_test['jwk_rsa_list']

    ACMERequestActions.set_directory_url(PEBBLE_TEST)
    ACMERequestActions.query_dir()
    self.acct_actions = ACMEAccountActions(ACMERequestActions(Nonce()))

    if create_account:
        self.acct_list = []
        for jwk in self.jwk_list:
            acct = ACMEAccount.init_by_create(
                jwk=jwk,
                acct_actions=self.acct_actions,
                contact=_TEST_CONTACTS
            )
            self.acct_list.append(acct)



class ACMEAccountInitTest(unittest.TestCase):

    def setUp(self) -> None:
        common_setup(self, create_account=False)
    
    def test_init_by_create(self):
        for jwk in self.jwk_list:
            with self.subTest(jwk=jwk):
                acct = ACMEAccount.init_by_create(
                    jwk=jwk,
                    acct_actions=self.acct_actions,
                    contact=_TEST_CONTACTS
                )
                # reponse 201-created if an account is created
                self.assertEqual(acct._resp.status_code, 201)

    def test_init_by_query(self):
        for jwk in self.jwk_list:
            with self.subTest(jwk=jwk):
                ACMEAccount.init_by_create(
                    jwk=jwk,
                    acct_actions=self.acct_actions,
                    contact=_TEST_CONTACTS
                )
                acct = ACMEAccount.init_by_query(
                    jwk=jwk,
                    acct_actions=self.acct_actions
                )
                # reponse 200-OK if an account is returned successfully
                self.assertEqual(acct._resp.status_code, 200)
    
    def tearDown(self) -> None:
        stop_pebble_docker(PEBBLE_CONTAINER, PEBBLE_CHALLTEST_CONTAINER)


class ACMEAccountActionsTest(unittest.TestCase):

    def setUp(self) -> None:
        common_setup(self, create_account=True)
        self.acct_list: List[ACMEAccount]
        # generate new key for account_key_rollover
        new_priv = rsa.generate_private_key(65537, 2048, default_backend())
        new_pub = new_priv.public_key()
        self.jwk_new = JWKRSA(
            priv_key=new_priv,
            n=new_pub.public_numbers().n,
            e=new_pub.public_numbers().e
        )
    
    def test_poll_acct_state(self):
        for acct in self.acct_list:
            acct.poll_acct_state()
            # expect 200-OK on success post-as-get poll
            self.assertEqual(acct._resp.status_code, 200)
    
    def test_update_account(self):
        for acct in self.acct_list:
            acct.update_account(contact=_TEST_CONTACTS_MOD)
            acct.poll_acct_state()

            # successful update will return 200-OK
            self.assertEqual(acct._resp.status_code, 200)
            self.assertCountEqual(_TEST_CONTACTS_MOD, acct.contact)
    
    def test_account_key_rollover(self):
        acct = self.acct_list[0]
        jwk_old = acct.jwk_obj
        acct.account_key_rollover(self.jwk_new)

        # successful rollover will return 200-OK
        self.assertEqual(acct._resp.status_code, 200)
        self.assertIs(acct.jwk_obj, self.jwk_new)

        acct.deactivate()
        with self.assertRaises(ACMEError):
            # ensure that the new jwk is used in server
            ACMEAccount.init_by_create(
                jwk=self.jwk_new,
                acct_actions=self.acct_actions,
                contact=_TEST_CONTACTS
            )
    
    def tearDown(self) -> None:
        stop_pebble_docker(PEBBLE_CONTAINER, PEBBLE_CHALLTEST_CONTAINER)


class ACMEAcountDeactivationTest(unittest.TestCase):

    def setUp(self) -> None:
        common_setup(self, create_account=True)

    def test_deactivate(self):
        for acct in self.acct_list:
            acct.deactivate()

            # successful deactivation will return 200-OK
            self.assertEqual(acct._resp.status_code, 200)
            self.assertEqual(acct.status, 'deactivated')
            # try to post or post-as-get to a deactivated account will 
            # have 401-Unauthorized
            with self.assertRaises(ACMEError) as caught:
                acct.poll_acct_state()
                self.assertEqual(caught.exception.status_code, 401)
    
    def tearDown(self) -> None:
        stop_pebble_docker(PEBBLE_CONTAINER, PEBBLE_CHALLTEST_CONTAINER)


class ACMEOrderNewTest(unittest.TestCase):

    def setUp(self) -> None:
        self.acct_list: List[ACMEAccount]
        common_setup(self, create_account=True)
        self.idf_list = [f'test-{i}.local' for i in range(len(self.acct_list))]
        self.idf_multi_list = [
            [f'test-{i}.local', f'test-{i}-m.local'] 
            for i in range(len(self.acct_list))
        ]
    
    def test_new_order_single_idf(self):
        """test new order with only one identifier"""
        for acct, idf in zip(self.acct_list, self.idf_list):
            order_obj = acct.new_order(identifiers=[idf])

            # successful order creation will return 201-created
            self.assertEqual(acct._resp.status_code, 201)
            self.assertEqual(len(acct.order_objs), 1)
            self.assertIs(order_obj, acct.order_objs[0])
            self.assertCountEqual([idf], order_obj.identifier_values)
    
    def test_new_order_multi_idf(self):
        """test new order with more than one identifiers"""
        for acct, idfs in zip(self.acct_list, self.idf_multi_list):
            order_obj = acct.new_order(identifiers=idfs)

            # successful order creation will return 201-created
            self.assertEqual(acct._resp.status_code, 201)
            self.assertCountEqual(idfs, order_obj.identifier_values)

    def tearDown(self) -> None:
        stop_pebble_docker(PEBBLE_CONTAINER, PEBBLE_CHALLTEST_CONTAINER)


class ACMEOrderActionTest(unittest.TestCase):

    def setUp(self) -> None:
        self.acct_list: List[ACMEAccount]
        common_setup(self, create_account=True)
        self.idf_list = [f'test-{i}.local' for i in range(len(self.acct_list))]
        # create order_objs for later actions, one order for each acct
        self.order_objs: List[ACMEOrder] = []
        for acct, idf in zip(self.acct_list, self.idf_list):
            order_obj = acct.new_order(identifiers=[idf])
            self.order_objs.append(order_obj)

    def test_acct_get_orders(self):
        loc_from_get: List[str] = []
        # order_objs from new_order()
        loc_from_new = [o.order_location for o in self.order_objs]
        for acct in self.acct_list:
            rtn_order_objs = acct.get_orders()
            # order_objs from get_orders()
            loc_from_get += [o.order_location for o in rtn_order_objs]
            
            self.assertEqual(len(acct.order_objs), 1)

        self.assertCountEqual(loc_from_get, loc_from_new)
    
    def test_poll_order_state(self):
        for order_obj in self.order_objs:
            order_obj.poll_order_state()

            # post-as-get to an order's location url
            self.assertEqual(order_obj._resp.status_code, 200)

    
    def tearDown(self) -> None:
        stop_pebble_docker(PEBBLE_CONTAINER, PEBBLE_CHALLTEST_CONTAINER)


class ACMEAuthorizationTest(unittest.TestCase):

    def setUp(self) -> None:
        common_setup(self, create_account=True)
        self.idf_multi_list = [
            [f'test-{i}.local', f'test-{i}-m.local'] 
            for i in range(len(self.acct_list))
        ]
        # each auth_obj represents one identifier in an order
        self.order_objs: List[ACMEOrder] = []
        for acct, idf_multi in zip(self.acct_list, self.idf_multi_list):
            order_obj = acct.new_order(identifiers=idf_multi)
            self.order_objs.append(order_obj)
    
    def test_poll_auth_state(self):
        for order_obj in self.order_objs:
            # at this moment each order has 2 identifiers, means 2 auth_obj
            self.assertEqual(len(order_obj.auth_objs), 2)

            auth_obj = order_obj.auth_objs[0]
            auth_obj.poll_auth_state()

            # post-as-get to auth location url
            self.assertEqual(auth_obj._resp.status_code, 200)

            # poll order, auth state will be implicitly updated
            order_obj.poll_order_state()
            self.assertEqual(len(order_obj.auth_objs), 2)
    
    def test_deactivate_auth(self):
        """deactivate one of the auth_obj for each order"""
        for order_obj in self.order_objs:
            auth_to_deactivate = order_obj.auth_objs[1]
            auth_to_deactivate.deactivate_auth()

            # successful deactivation will return 200-OK
            self.assertEqual(auth_to_deactivate._resp.status_code, 200)
            self.assertEqual(auth_to_deactivate.status, "deactivated")

            # now the order state will also become "deactivated"
            order_obj.poll_order_state()
            self.assertEqual(order_obj.status, "deactivated")
    
    def tearDown(self) -> None:
        stop_pebble_docker(PEBBLE_CONTAINER, PEBBLE_CHALLTEST_CONTAINER)


class ACMEChallengeTest(unittest.TestCase):

    def setUp(self) -> None:
        common_setup(self, create_account=True)
        self.idf_multi_list = [
            [f'test-{i}.local', f'test-{i}-m.local'] 
            for i in range(len(self.acct_list))
        ]
        # each auth_obj represents one identifier in an order
        self.order_objs: List[ACMEOrder] = []
        for acct, idf_multi in zip(self.acct_list, self.idf_multi_list):
            order_obj = acct.new_order(identifiers=idf_multi)
            self.order_objs.append(order_obj)
    
    def test_respond(self):
        for order_obj in self.order_objs:
            order_obj.poll_order_state()
            for auth_obj in order_obj.auth_objs:
                # respond to http challenge
                jwk = order_obj.related_acct.jwk_obj

                # pebble challtest service
                add_http_01(auth_obj.chall_http.token, jwk)

                auth_obj.chall_http.respond()

                # poll immediately should have "pending" state
                auth_obj.poll_auth_state()
                self.assertEqual(auth_obj.status, 'pending')

                # wait for challenges to complete
                time.sleep(5)
                auth_obj.poll_auth_state()
                status = auth_obj.chall_http.status

                # chall object state should become "valid"
                self.assertEqual(status, 'valid')
                self.assertEqual(auth_obj.status, 'valid')
            
            # once all auth valid, order state become "ready"
            order_obj.poll_order_state()
            self.assertEqual(order_obj.status, 'ready')

    def tearDown(self) -> None:
        stop_pebble_docker(PEBBLE_CONTAINER, PEBBLE_CHALLTEST_CONTAINER)