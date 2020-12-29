
from run_pyacme import main
from typing import Dict, List
from pathlib import Path
import json
import subprocess
import unittest
import time

# for running this file directly
import sys
# sys.path.append(str(Path(__file__).parents[0].absolute()))
sys.path.append(str(Path(__file__).parents[1].absolute()))

from pyacme.settings import CERT_CHAIN, CERT_NAME, WD_DEFAULT, WD_CERT
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

    if main_param['no_ssl_verify']:
        run_arg += ['--no_ssl_verify']
    del main_param['no_ssl_verify']

    for k, v in main_param.items():
        run_arg += [param_dict[k], v]
    p = subprocess.run(
        run_arg,
        capture_output=True,
        # check=True
    )
    return p


class SingleDomain(unittest.TestCase):

    def setUp(self) -> None:
        run_pebble_standalone_container()
        # add to host file manually if sudo is not intended
        self.domain = ['test-integration.local']
        self.aliyun_ak = get_aliyun_access_key('test/.aliyun_dns_api.json')
    
    def test_http_run(self):
        # add_host_entry(self.domain, '127.0.0.1')
        self.p = subprocess_run_pyacme(
            domain=self.domain,
            contact=TEST_CONTACTS,
            country_code='UN',
            mode='http',
            CA_entry=PEBBLE_TEST,
            no_ssl_verify=True,
            chall_resp_server_port=PY_HTTPSERVER_PORT
        )
        self.assertEqual(self.p.returncode, 0)
        wd = Path(WD_DEFAULT).expanduser().absolute() / self.domain[0]
        download_root_cert(wd / WD_CERT)
        openssl_verify(
            cert_path=wd / WD_CERT / CERT_NAME,
            chain_path=wd / WD_CERT / CERT_CHAIN,
            root_cert_path=wd / WD_CERT
        )

    def tearDown(self) -> None:
        stop_pebble_standalone_container()
        print(self.p.stderr.decode('utf-8'))
        print(self.p.stdout.decode('utf-8'))