"""
run a standalone http server instead of pebble-challtest to serve the challenge 
text to pebble.

user password needed for sudo, run this script with `python -m unittest`
"""
from typing import List
from pathlib import Path
import subprocess
import unittest
import time

# for running this file directly
import sys
# sys.path.append(str(Path(__file__).parents[0].absolute()))
sys.path.append(str(Path(__file__).parents[1].absolute()))

from pyacme.util import get_keyAuthorization, generate_rsa_privkey
from pyacme.actions import ACMEAccountActions
from pyacme.jwk import JWKRSA
from pyacme.ACMEobj import ACMEAccount
from pyacme.request import ACMERequestActions
from pyacme.settings import PEBBLE_TEST

from test_common import *


PY_HTTPSERVER_IP = '127.0.0.2'
PY_HTTPSERVER_PORT = '5002'
CHALLENGE_PATH = BASE / 'test' / 'statics' / '.well-known' / 'acme-challenge'
HTTP_SERVER_PATH = BASE / 'test' / 'statics'
IDENTIFIERS = ['test-11.local', 'test-22.local']


def clear_chall_path():
    for f in CHALLENGE_PATH.iterdir():
        f.unlink()


def add_host_entry(domains: List[str], addr = PY_HTTPSERVER_IP) -> None:
    """
    add entry like `127.0.0.1 test.local` to /etc/hosts, if entry exists, skip
    """
    def _sudo_sed(domain: str) -> subprocess.CompletedProcess:
        p = subprocess.run(
            [
                'sudo', 
                'sed', '-i',
                '$a\\' + f'{addr} {domain}',
                '/etc/hosts'
            ],
            check=True
        )
        return p
    
    # check the content of hosts
    checked_p = subprocess.run(
        ['sudo', 'cat', '/etc/hosts'], 
        capture_output=True
    )
    entries = checked_p.stdout.decode('utf-8').split('\n')
    
    for domain in domains:
        for entry in entries:
            if domain in entry:
                print(f'{domain} exists in /etc/hosts')
                break
        else:
            _sudo_sed(domain)
            print(f'{domain} added to /etc/hosts')


def run_pebble_standalone_container(name: str = 'pebble'):
    """run a pebble container using host's network"""
    p = subprocess.run(
        [
            'docker', 'run', 
            '-d', 
            '-e', '"PEBBLE_VA_NOSLEEP=1"', 
            '--network=host',
            '--name', name,
            'letsencrypt/pebble'
        ],
        check=False,
        capture_output=True
    )
    if p.returncode != 0:
        raise ValueError(p.stderr.decode('utf-8'))
    time.sleep(SLEEP_AFTER_DOCKER)


def stop_pebble_standalone_container(name: str = 'pebble') -> None:
    subprocess.run(['docker', 'stop', name], check=True)
    subprocess.run(['docker', 'container', 'prune', '-f'], check=True)


def create_py_http_server(bind: str, port: str, path: str) -> subprocess.Popen:
    p =  subprocess.Popen(
        [
            'python', '-m', 'http.server', 
            '--bind', bind,
            '--directory', path,
            port
        ]
    )
    print(f'server created at pid={p.pid}')
    return p


class StandaloneHttpChallengeTest(unittest.TestCase):

    def setUp(self) -> None:
        try:
            clear_chall_path()
            run_pebble_standalone_container()
            download_root_cert(CERT_DIR)
            (pub, priv), priv_path = load_test_keys(
                (str(RSA_PUB_1), str(RSA_PRIV_1))
            )[0]
            self.jwk = JWKRSA(
                priv_key=priv,
                n=pub.public_numbers().n,
                e=pub.public_numbers().e
            )
            ACMERequestActions.set_directory_url(PEBBLE_TEST)
            ACMERequestActions.query_dir()
            req_action = ACMERequestActions()
            req_action.new_nonce()
            self.acct_action = ACMEAccountActions(req_action=req_action)

            self.http_p = create_py_http_server(
                bind=PY_HTTPSERVER_IP,
                port=PY_HTTPSERVER_PORT,
                path=str(HTTP_SERVER_PATH)
            )

            self.priv_key_for_finalize = generate_rsa_privkey(str(CERT_DIR))
        except (subprocess.CalledProcessError, OSError):
            if hasattr(self, 'http_p'):
                self.http_p.terminate()
            stop_pebble_standalone_container()
    
    def test_chall_respond_http(self):
        acct_obj = ACMEAccount.init_by_create(
            jwk=self.jwk, 
            acct_actions=self.acct_action,
            contact=TEST_CONTACTS
        )
        # create new account
        self.assertEqual(acct_obj._resp.status_code, 201)
        # create new order using 2 identifiers
        order_obj = acct_obj.new_order(identifiers=IDENTIFIERS)
        self.assertEqual(order_obj._resp.status_code, 201)
        order_obj.poll_order_state()
        self.assertCountEqual(order_obj.identifier_values, IDENTIFIERS)
        # 2 auth_obj should exist now
        self.assertEqual(len(order_obj.auth_objs), 2)

        # write challenge content to rfc8555 defined path
        for auth_obj in order_obj.auth_objs:
            add_host_entry([auth_obj.identifier_value])
            chall_text_path = CHALLENGE_PATH / auth_obj.chall_http.token
            with open(chall_text_path.absolute(), 'w') as f:
                chall_content = get_keyAuthorization(
                    token=auth_obj.chall_http.token,
                    jwk=acct_obj.jwk_obj
                )
                f.write(chall_content)
            auth_obj.chall_http.respond()
            # at least 5s, as pebble will send 3 requests to the standalone
            # http server, during the 3 requests, auth_obj.status is "pending"
            time.sleep(5)
        
            # auth_obj status now should be 'valid'
            auth_obj.poll_auth_state()
            self.assertEqual(auth_obj.status, 'valid')
        
        # all auth_obj valid, order status should be 'ready'
        order_obj.poll_order_state()
        self.assertEqual(order_obj.status, 'ready')

        # finalize order obj
        order_obj.finalize_order(
            privkey=self.priv_key_for_finalize,
            engine='cryptography',
            C='CN',
            O='Test Org',
            emailAddress='test@email.local'
        )
        order_obj.poll_order_state()
        # after finalization, order status become 'valid'
        self.assertEqual(order_obj.status, 'valid')

        # download certificate
        download_resp = order_obj.download_certificate(CERT_DIR)
        self.assertEqual(download_resp.status_code, 200)

        openssl_verify(CERT_DIR/'cert.pem', CERT_DIR/'chain.pem')
    
    def tearDown(self) -> None:
        self.http_p.terminate()
        stop_pebble_standalone_container()
        

# if __name__ == "__main__":
#     try:
#         p = run_pebble_standalone_container()
#     except subprocess.CalledProcessError:
#         print(p.stdout)
#         print(p.stderr)