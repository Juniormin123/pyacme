from typing import List, Tuple, Union
from pathlib import Path
import time
import json
import subprocess

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# for running this file directly
import sys
sys.path.append(str(Path(__file__).parents[1].absolute()))

from pyacme.base import _JWKBase
from pyacme.util import get_keyAuthorization, get_dns_chall_txt_record
# from pyacme.settings import *
from test_settings import *


# test constants
BASE = Path(__file__).parents[1].absolute()
RSA_PUB_1 = BASE / 'test' / 'test_pubkey.pem'
RSA_PRIV_1 = BASE / 'test' / 'test_privkey.pem'
RSA_PUB_2 = BASE / 'test' / 'test_pubkey_2.pem'
RSA_PRIV_2 = BASE / 'test' / 'test_privkey_2.pem'

CERT_DIR = BASE / 'test' / '.cert_files'
CERT_DIR.mkdir(parents=True, exist_ok=True)

TEST_CONTACTS = ['mailto:min641366609@live.com']
TEST_CONTACTS_MOD = ['mailto:calvin.cheng@synergyfutures.com']

SLEEP_AFTER_DOCKER = 4

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
    time.sleep(SLEEP_AFTER_DOCKER)
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


def add_dns_01(token: str, domain: str, jwk: _JWKBase) -> requests.Response:
    """
    add dns-01 challenge respond to pebble challtest
    """
    value = get_dns_chall_txt_record(token, jwk)
    domain = f'_acme-challenge.{domain}.'
    resp = requests.post(
        url=PEBBLE_CHALLTEST_DNS01,
        data=json.dumps({'host': domain, 'value': value})
    )
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


T = List[Tuple[tuple, str]]


def load_test_keys(*key_pair_path: Tuple[str, str]) -> T:
    """
    load pem file into key object
    """
    key_pairs: T = []
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


def download_root_cert(root_cert_path: Path, 
                       url: str = 'https://localhost:15000/roots/0',
                       name = "pebble-root-cert.pem"):
    """download root cert from pebble container"""
    subprocess.run(
        [
            'wget', url, 
            '--no-check-certificate',
            '-O', f'{root_cert_path/name!s}',
            '--quiet'
        ]
    )


def openssl_verify(cert_path: Union[Path, str], 
                   chain_path: Union[Path, str], 
                   root_cert_path = CERT_DIR,
                   root_cert_name = "pebble-root-cert.pem"):
    """run `openssl verify` on downloaded cert"""
    p = subprocess.run(
        [
            'openssl', 'verify',
            '-CAfile', f'{root_cert_path/root_cert_name!s}',
            '-untrusted', str(chain_path),
            str(cert_path)
        ]
    )
    return p


def add_host_entry(domains: List[str], addr: str) -> None:
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


if __name__ == '__main__':
    print(Path(__file__).parent)