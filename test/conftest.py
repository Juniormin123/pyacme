from pathlib import Path
import sys
# sys.path.append(str(Path(__file__).parents[0].absolute()))
sys.path.append(str(Path(__file__).parents[1].absolute()))

from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend

import pytest

from pyacme.ACMEobj import ACMEAccount, ACMEOrder
from pyacme.actions import ACMEAccountActions
from pyacme.request import ACMERequestActions
from pyacme.base import _JWKBase, _JWSBase
from pyacme.jwk import JWKRSA, JWKES256
from pyacme.jws import JWSRS256
from pyacme.exceptions import ACMEError
from pyacme import settings

from test_common import *


DEFAULT_KEYSIZE = 2048


def pytest_configure(config):
    config.addinivalue_line(
        'markers', 'domain(identifier): valid domain names'
    )
    config.addinivalue_line(
        'markers', 'docker_type(type_value)'
    )
    config.addinivalue_line(
        'markers', 'dnstest'
    )
    config.addinivalue_line(
        'markers', 'dnstest_pebble'
    )
    config.addinivalue_line(
        'markers', 'httptest'
    )
    config.addinivalue_line(
        'markers', 'host_entry'
    )


@pytest.fixture(scope='module', autouse=True)
def setup_pebble_docker():
    print('using docker-compose setup')
    # this will run the pebble docker-compose, including challtest
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


def _new_ec_privkey(curve) -> ec.EllipticCurvePrivateKey:
    csr_priv_key = ec.generate_private_key(curve, default_backend())
    return csr_priv_key


@pytest.fixture(scope='function')
def new_rsa_privkey() -> rsa.RSAPrivateKey:
    return _new_rsa_privkey()


@pytest.fixture(scope='function')
def new_rsa_privkey_i() -> rsa.RSAPrivateKey:
    return _new_rsa_privkey()


def _new_jwk(request, new_rsa_privkey) -> _JWKBase:
    jwk_type = request.param
    if jwk_type == 'rsa':
        jwk = JWKRSA(
            priv_key=new_rsa_privkey,
            n=new_rsa_privkey.public_key().public_numbers().n,
            e=new_rsa_privkey.public_key().public_numbers().e
        )
        return jwk
    elif jwk_type == 'es256':
        jwk = JWKES256(priv_key=_new_ec_privkey(ec.SECP256R1()))
        return jwk
    else:
        raise ValueError(f'jwk type {jwk_type} not supported')


@pytest.fixture(scope='function', params=['rsa', 'es256'])
def new_jwk(request, new_rsa_privkey: rsa.RSAPrivateKey) -> _JWKBase:
   return  _new_jwk(request, new_rsa_privkey)


@pytest.fixture(scope='function', params=['rsa', 'es256'])
def new_jwk_i(request, new_rsa_privkey_i: rsa.RSAPrivateKey) -> _JWKBase:
    # for new jwk which is independent of new account
    return _new_jwk(request, new_rsa_privkey_i)


@pytest.fixture(scope='function')
def new_acct_action(new_request_action) -> ACMEAccountActions:
    return ACMEAccountActions(new_request_action)


@pytest.fixture(scope='function')
def new_acct_obj(new_jwk, new_acct_action) -> ACMEAccount:
    acct = ACMEAccount.init_by_create(
        jwk=new_jwk, 
        acct_actions=new_acct_action,
        contact=TEST_CONTACTS
    )
    return acct


@pytest.fixture(scope='function')
def new_order_obj(request, new_acct_obj: ACMEAccount) -> ACMEOrder:
    # domain will be supplied by test using markder
    marker = request.node.get_closest_marker('domain')
    if marker is None:
        # if no marker, domain supplied by test instance attr "domain"
        domain = getattr(request.instance, 'domain', ['test.local'])
    else:
        domain = marker.args
    return new_acct_obj.new_order(identifiers=domain)


@pytest.fixture(scope='function')
def new_ready_order(request, new_order_obj: ACMEOrder) -> ACMEOrder:
    jwk = new_order_obj.related_acct.jwk_obj
    auth = new_order_obj.auth_objs[0]
    add_http_01(auth.chall_http.token, jwk)
    auth.chall_http.respond()
    time.sleep(4)
    return new_order_obj


@pytest.fixture(scope='function')
def new_tmp_wd(tmp_path: Path):
    wd = tmp_path / CERT_DIR
    wd.mkdir(parents=True, exist_ok=True)
    yield wd, wd/'cert.pem', wd/'chain.pem', wd/'fullchain.pem'
    print('clearing temp path')
    for p in wd.iterdir():
        p.unlink()
        print(f'{p!s} cleared')
