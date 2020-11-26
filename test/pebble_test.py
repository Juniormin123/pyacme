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

from typing import Any, Dict, List, Tuple
from pathlib import Path
import time
import json
import subprocess
import unittest
from unittest.case import skip

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# for running this file directly
import sys
sys.path.append(str(Path(__file__).parents[1].absolute()))

from pyacme.base import _JWKBase
from pyacme.util import get_keyAuthorization
from pyacme.jwk import JWKRSA
from pyacme.jws import JWSRS256
from pyacme.exceptions import ACMEError
from pyacme.actions import ACMEAccountActions
from pyacme.ACMEobj import ACMEAccount
from pyacme.requests import ACMERequestActions, Nonce
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


def load_test_keys(*key_pair_path) -> List[tuple]:
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
        key_pairs.append((pub_key, priv_key))
    return key_pairs


# set up RSA variables
def _set_up_rsa(self):
    self.rsa_test = dict()
    self.rsa_test['key_pair'] = load_test_keys(
        (_RSA_PUB_1, _RSA_PRIV_1),
        (_RSA_PUB_2, _RSA_PRIV_2)
    )
    self.rsa_test['jwk_rsa_list'] = []
    for key_pair in self.rsa_test['key_pair']:
        jwk_rsa = JWKRSA(
            priv_key=key_pair[1],
            n=key_pair[0].public_numbers().n,
            e=key_pair[0].public_numbers().e
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


class ACMEAccountActionsTest(unittest.TestCase):

    def setUp(self) -> None:
        run_pebble_docker(str(PEBBLE_DOCKER_FILE))
        _set_up_rsa(self)

        # other key type setup

        self.jws_types = [JWSRS256]
        self.jwk_list = [self.rsa_test['jwk_rsa_list']]    # type: ignore

        # set pebble addr for testing
        ACMERequestActions.set_directory_url(PEBBLE_TEST)
        ACMERequestActions.query_dir()
        self.acct_actions = ACMEAccountActions(ACMERequestActions(Nonce()))
    
    def test_new_nonce(self):
        """get a new nonce, should retry if badNonce error raised"""
        nonce = self.acct_actions.req_action.new_nonce()
        self.assertNotEqual(nonce, '')
    
    def test_create_acct(self):
        """test account creation using pebble"""
        self.acct_actions.req_action.new_nonce()
        # make sure jws and jwk are paired
        for jws_type, jwk_list in zip(self.jws_types, self.jwk_list):
            with self.subTest(jws_type=jws_type, jwk_list=jwk_list):
                acct = self.acct_actions.create_acct(
                    jwk=jwk_list[0],
                    contact=_TEST_CONTACTS,
                    jws_type=jws_type
                )
                self.assertIsInstance(acct, ACMEAccount)
                # new account created, status code 201-created
                self.assertEqual(acct._resp.status_code, 201)
                # required fields check
                self.assertTrue(hasattr(acct, 'status'))
                self.assertTrue(hasattr(acct, 'orders'))
                # values for required field should not be empty
                self.assertTrue(acct.status)
                self.assertTrue(acct.orders)
    
    def test_query_acct(self):
        # create a new account so that this test can be run independently
        self.acct_actions.req_action.new_nonce()
        for jws_type, jwk_list in zip(self.jws_types, self.jwk_list):
            with self.subTest(jws_type=jws_type, jwk_list=jwk_list):
                # use the key_2
                self.acct_actions.create_acct(
                    jwk=jwk_list[1],
                    contact=_TEST_CONTACTS,
                    jws_type=jws_type
                )
                # acct_obj returned from query
                acct = self.acct_actions.query_acct(jwk_list[1], jws_type)
                self.assertIsInstance(acct, ACMEAccount)
                # existed account query, status code 200-OK
                self.assertEqual(acct._resp.status_code, 200)
    
    def test_update_acct(self):
        if global_docker_is_running:
            restart_pebble_docker(
                PEBBLE_DOCKER_FILE, 
                PEBBLE_CONTAINER, 
                PEBBLE_CHALLTEST_CONTAINER
            )
        self.acct_actions.req_action.new_nonce()
        for jws_type, jwk_list in zip(self.jws_types, self.jwk_list):
            with self.subTest(jws_type=jws_type, jwk_list=jwk_list):
                acct = self.acct_actions.create_acct(
                    jwk=jwk_list[0],
                    contact=_TEST_CONTACTS,
                    jws_type=jws_type
                )
                acct_updated = self.acct_actions.update_acct(
                    acct_obj=acct,
                    jws_type=jws_type,
                    contact=_TEST_CONTACTS_MOD
                )
                # check whether same object updated
                self.assertIs(acct, acct_updated)
                # expect 200-OK and return acct object
                # also test for whether acct_obj itself is updated, if not, 
                # the status code is still 201 from create_acct(), which is not
                # intended here
                self.assertEqual(acct_updated._resp.status_code, 200)
                self.assertEqual(acct._resp.status_code, 200)
                # check whether contact info is updated
                self.assertCountEqual(acct.contact, _TEST_CONTACTS_MOD)
    
    @unittest.skip('not implemented for now')
    def test_external_acct_binding(self):
        pass

    def test_acct_key_rollover(self):
        if global_docker_is_running:
            restart_pebble_docker(
                PEBBLE_DOCKER_FILE, 
                PEBBLE_CONTAINER, 
                PEBBLE_CHALLTEST_CONTAINER
            )
        self.acct_actions.req_action.new_nonce()
        for jws_type, jwk_list in zip(self.jws_types, self.jwk_list):
            with self.subTest(jws_type=jws_type, jwk_list=jwk_list):
                acct = self.acct_actions.create_acct(
                    jwk=jwk_list[0],
                    contact=_TEST_CONTACTS,
                    jws_type=jws_type
                )
                acct_key_rolled = self.acct_actions.acct_key_rollover(
                    acct_obj=acct,
                    # roll over the key pair 2
                    jwk_new=jwk_list[1],
                    jws_type=jws_type
                )
                # check whether same object updated
                self.assertIs(acct, acct_key_rolled)
                # expect 200-OK and return updated acct object
                self.assertEqual(acct_key_rolled._resp.status_code, 200)
                self.assertEqual(acct._resp.status_code, 200)
                # check new key status
                self.assertEqual(acct.jwk_obj.n, jwk_list[1].n)
                # use the old key should raise error now
                self.assertRaises(
                    ACMEError,
                    self.acct_actions.query_acct,
                    jwk_list[0], 
                    jws_type
                )
    
    def test_deactivate_acct(self):
        if global_docker_is_running:
            restart_pebble_docker(
                PEBBLE_DOCKER_FILE, 
                PEBBLE_CONTAINER, 
                PEBBLE_CHALLTEST_CONTAINER
            )
        self.acct_actions.req_action.new_nonce()
        for jws_type, jwk_list in zip(self.jws_types, self.jwk_list):
            with self.subTest(jws_type=jws_type, jwk_list=jwk_list):
                acct = self.acct_actions.create_acct(
                    jwk=jwk_list[0],
                    contact=_TEST_CONTACTS,
                    jws_type=jws_type
                )
                acct_deactivated = self.acct_actions.deactivate_acct(
                    acct_obj=acct,
                    jws_type=jws_type
                )
                # check whether same object updated
                self.assertIs(acct, acct_deactivated)
                # expect 200-OK and return deactivated acct object
                self.assertEqual(acct_deactivated._resp.status_code, 200)
                self.assertEqual(acct._resp.status_code, 200)
                # POST or POST-as-GET to a deactivated account will have error
                self.assertRaises(
                    ACMEError,
                    self.acct_actions.query_acct,
                    jwk_list[0],
                    jws_type
                )
    
    def tearDown(self) -> None:
        stop_pebble_docker(PEBBLE_CONTAINER, PEBBLE_CHALLTEST_CONTAINER)
    