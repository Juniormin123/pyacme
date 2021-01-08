
from typing import Dict, List
from pathlib import Path
import json
import subprocess
import unittest

# for running this file directly
import sys
# sys.path.append(str(Path(__file__).parents[0].absolute()))
sys.path.append(str(Path(__file__).parents[1].absolute()))

from pyacme.settings import CERT_CHAIN, CERT_NAME, LETSENCRYPT_STAGING, WD_DEFAULT, WD_CERT
from test_common import *


PY_HTTPSERVER_PORT = '5002'


def get_aliyun_access_key(key_file: str) -> Dict[str, str]:
    with open(key_file, 'r') as f:
        return json.load(f)


def subprocess_run_pyacme(**main_param) -> subprocess.CompletedProcess:
    run_arg = ['python', str(Path(__file__).parents[1] / 'run_pyacme.py')]
    param_dict = {
        'country_code': '-C',
        'csr_subjects': '--csr_subjects',
        'account_private_key': '--account_private_key',
        'not_before': '--not_before',
        'not_after': '--not_after',
        'working_directory': '-w',
        'mode': '-m',
        'dnsprovider': '--dnsprovider',
        'access_key': '-k',
        'secret': '-s',
        'dns_specifics': '--dns_specifics',
        'CA_entry': '--CA_entry',
        'poll_interval': '--poll_interval',
        'poll_retry_count': '--poll_retry_count',
        'csr_priv_key_type': '--csr_priv_key_type',
        'csr_priv_key_size': '--csr_priv_key_size',
        'chall_resp_server_port': '--chall_resp_server_port',
    }

    for d in main_param['domain']:
        run_arg += ['-d', d]
    del main_param['domain']

    for c in main_param['contact']:
        run_arg += ['-c', c]
    del main_param['contact']

    if ('no_ssl_verify' in main_param) and main_param['no_ssl_verify']:
        run_arg += ['--no_ssl_verify']
        del main_param['no_ssl_verify']

    if ('debug' in main_param) and main_param['debug']:
        run_arg += ['--debug']
        del main_param['debug']

    for k, v in main_param.items():
        run_arg += [param_dict[k], v]
    p = subprocess.run(
        run_arg,
        # capture_output=True,
        # check=True
    )
    return p


def _common(self, params: dict, ca = 'pebble'):
    self.p = subprocess_run_pyacme(**params)
    self.assertEqual(self.p.returncode, 0)
    if 'working_directory' in params:
        wd = Path(params['working_directory']).expanduser().absolute()
    else:
        wd = Path(WD_DEFAULT).expanduser().absolute()
    wd = wd / '_'.join(params['domain'])    # domain must exist
    root_cert = 'pebble-root-cert.pem'
    if ca == 'pebble':
        download_root_cert(wd / WD_CERT)
        root_cert = 'pebble-root-cert.pem'
    elif ca == 'staging':
        download_root_cert(wd / WD_CERT, STAGING_ROOT_CA, 'fake_root.pem')
        root_cert = 'fake_root.pem'
    verify_p = openssl_verify(
        cert_path=wd / WD_CERT / CERT_NAME,
        chain_path=wd / WD_CERT / CERT_CHAIN,
        root_cert_path=wd / WD_CERT,
        root_cert_name=root_cert
    )
    self.assertEqual(verify_p.returncode, 0)


class IntegrationHttpMode(unittest.TestCase):

    def setUp(self) -> None:
        run_pebble_standalone_container()
        # add to host file manually if sudo is not intended
        self.domain = ['test-integration.local']
        self.multi_domain = [
            'a.test-integration.local', 'b.test-integration.local'
        ]
    
    def test_http_run(self):
        params = dict(
            domain=self.domain,
            contact=TEST_CONTACTS,
            country_code='UN',
            mode='http',
            CA_entry=PEBBLE_TEST,
            no_ssl_verify=True,
            chall_resp_server_port=PY_HTTPSERVER_PORT
        )
        _common(self, params)

    def test_http_multi_domain(self):
        params = dict(
            domain=self.multi_domain,
            contact=TEST_CONTACTS,
            country_code='UN',
            mode='http',
            CA_entry=PEBBLE_TEST,
            no_ssl_verify=True,
            chall_resp_server_port=PY_HTTPSERVER_PORT
        )
        _common(self, params)

    def test_http_run_debug_output(self):
        params = dict(
            domain=self.domain,
            contact=TEST_CONTACTS,
            country_code='UN',
            mode='http',
            CA_entry=PEBBLE_TEST,
            no_ssl_verify=True,
            chall_resp_server_port=PY_HTTPSERVER_PORT,
            debug=True
        )
        _common(self, params)

    def test_http_new_wd(self):
        params = dict(
            domain=self.domain,
            contact=TEST_CONTACTS,
            country_code='UN',
            mode='http',
            CA_entry=PEBBLE_TEST,
            no_ssl_verify=True,
            chall_resp_server_port=PY_HTTPSERVER_PORT,
            working_directory='~/.pyacme/new'
        )
        _common(self, params)

    def tearDown(self) -> None:
        stop_pebble_standalone_container()
        # print(self.p.stderr.decode('utf-8'))
        # print(self.p.stdout.decode('utf-8'))


class IntegrationDNSModeStaging(unittest.TestCase):

    def setUp(self) -> None:
        # run_pebble_standalone_container()
        self.domain = ['test-staging.xn--jhqy4a5a064kimjf01df8e.host']
        self.wild_card_domain = ['*.xn--jhqy4a5a064kimjf01df8e.host']
        self.multi_domain = [
            'test-staging-1.xn--jhqy4a5a064kimjf01df8e.host',
            'test-staging-2.xn--jhqy4a5a064kimjf01df8e.host',
        ]
        # self.domain = ['xn--jhqy4a5a064kimjf01df8e.host']
        self.aliyun_ak = get_aliyun_access_key('test/.aliyun_dns_api.json')
    
    def test_dns_run(self):
        params = dict(
            domain=self.domain,
            contact=TEST_CONTACTS,
            country_code='UN',
            CA_entry=LETSENCRYPT_STAGING,
            access_key=self.aliyun_ak['access_key'],
            secret=self.aliyun_ak['secret']
        )
        _common(self, params, ca='staging')
    
    def test_dns_wildcard(self):
        params = dict(
            domain=self.wild_card_domain,
            contact=TEST_CONTACTS,
            country_code='UN',
            CA_entry=LETSENCRYPT_STAGING,
            access_key=self.aliyun_ak['access_key'],
            secret=self.aliyun_ak['secret']
        )
        _common(self, params, ca='staging')

    def test_dns_mutlti_domain(self):
        params = dict(
            domain=self.multi_domain,
            contact=TEST_CONTACTS,
            country_code='UN',
            CA_entry=LETSENCRYPT_STAGING,
            access_key=self.aliyun_ak['access_key'],
            secret=self.aliyun_ak['secret'],
            debug=True
        )
        _common(self, params, ca='staging')