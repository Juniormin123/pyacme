import pytest

from pathlib import Path
import sys
# sys.path.append(str(Path(__file__).parents[0].absolute()))
sys.path.append(str(Path(__file__).parents[1].absolute()))

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from pyacme.ACMEobj import ACMEAccount
from pyacme.actions import ACMEAccountActions
from pyacme.request import ACMERequestActions
from pyacme.base import _JWKBase, _JWSBase
from pyacme.jwk import JWKRSA, JWSRS256

from test_common import *


DEFAULT_KEYSIZE = 2048


@pytest.fixture(scope='module', autouse=True)
def start_pebble_docker_compose():
    run_pebble_docker(PEBBLE_DOCKER_FILE)
    yield
    # cleanup and stop running container
    stop_pebble_docker(PEBBLE_CONTAINER, PEBBLE_CHALLTEST_CONTAINER)


@pytest.fixture(scope='module')
def new_request_action() -> ACMERequestActions:
    ACMERequestActions.set_directory_url(PEBBLE_TEST)
    ACMERequestActions.verify = False
    ACMERequestActions.query_dir()
    req = ACMERequestActions()
    req.new_nonce()
    return req


def _new_rsa_privkey() -> rsa.RSAPrivateKey:
    csr_priv_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=DEFAULT_KEYSIZE,
        backend=default_backend()
    )
    return csr_priv_key


@pytest.fixture(scope='function')
def new_rsa_privkey() -> rsa.RSAPrivateKey:
    """
    return RSAPrivatekey object
    """
    return _new_rsa_privkey()


@pytest.fixture(scope='function', params=['rsa'])
def new_jwk(request, new_rsa_privkey: rsa.RSAPrivateKey) -> _JWKBase:
    jwk_type = request.param
    if jwk_type == 'rsa':
        jwk = JWKRSA(
            priv_key=new_rsa_privkey,
            n=new_rsa_privkey.public_key().public_numbers().n,
            e=new_rsa_privkey.public_key().public_numbers().e
        )
        return jwk
    # elif:
    # more jwk type
    else:
        raise ValueError(f'jwk type {jwk_type} not supported')


@pytest.fixture(scope='function')
def new_acct_obj(new_jwk, new_request_action) -> ACMEAccount:
    acct_action = ACMEAccountActions(new_request_action)
    acct = ACMEAccount.init_by_create(
        jwk=new_jwk, 
        acct_actions=acct_action,
        contact=TEST_CONTACTS
    )
    return acct