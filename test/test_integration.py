from pyacme.settings import LETSENCRYPT_STAGING
import pytest

from conftest import Path
from conftest import settings
from test_common import *


# def pytest_configure(config):
#     config.addinivalue_line(
#         'markers', 'docker_type(type_value)'
#     )


@pytest.fixture(scope='class')
def setup_pebble_docker(request):
    # override start_pebble_docker form conftest.py
    marker = request.node.get_closest_marker('docker_type')
    if marker.args[0] == 'standalone':
        print('using standalone container setup')
        # override start_pebble_docker() from conftest.py;
        # only run the pebble container, without challtest
        container_name = time.strftime(settings.BAK_TIME_FMT, time.localtime())
        container_name = 'pebble_' + container_name
        run_pebble_standalone_container(container_name)
        print(f'running container {container_name}')
        yield
        stop_pebble_standalone_container(container_name)
    elif marker.args[0] is None:
        # do not run any container
        yield


@pytest.fixture(scope='function')
def aliyun_access_key() -> Dict[str, str]:
    try:
        with open('./.aliyun_dns_api.json') as f:
            return json.load(f)
    except FileNotFoundError:
        with open('test/.aliyun_dns_api.json') as f:
            return json.load(f)


def get_aliyun_access_key(key_file: str) -> Dict[str, str]:
    with open(key_file, 'r') as f:
        return json.load(f)


def subprocess_run_pyacme(**main_param) -> subprocess.CompletedProcess:
    run_arg = [sys.executable, str(Path(__file__).parents[1] / 'run_pyacme.py')]
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


def _common(params: dict, ca = 'pebble'):
    assert subprocess_run_pyacme(**params).returncode == 0
    if 'working_directory' in params:
        wd = Path(params['working_directory']).expanduser().absolute()
    else:
        wd = Path(settings.WD_DEFAULT).expanduser().absolute()
    wd = wd / '_'.join(params['domain'])    # domain must exist
    root_cert = 'pebble-root-cert.pem'
    if ca == 'pebble':
        download_root_cert(wd/settings.WD_CERT)
        root_cert = 'pebble-root-cert.pem'
    elif ca == 'staging':
        root_cert = 'fake_root.pem'
        download_root_cert(wd/settings.WD_CERT, STAGING_ROOT_CA, root_cert)
    verify_p = openssl_verify(
        cert_path=wd/settings.WD_CERT/settings.CERT_NAME,
        chain_path=wd/settings.WD_CERT/settings.CERT_CHAIN,
        root_cert_path=wd/settings.WD_CERT,
        root_cert_name=root_cert
    )
    assert verify_p.returncode == 0


_DOMAIN = ['test-integration.local']
_MULTI_DOMAIN = ['a.test-integration.local', 'b.test-integration.local']
_HTTP_MODE_COMMON_PARAM_PORTION = dict(
    contact=TEST_CONTACTS,
    country_code='UN',
    CA_entry=PEBBLE_TEST,
    mode='http',
    no_ssl_verify=True,
    chall_resp_server_port=PY_HTTPSERVER_PORT,
)

http_mode_params = [
    pytest.param(
        dict(domain=_DOMAIN, **_HTTP_MODE_COMMON_PARAM_PORTION),
        id='http_mode_single_domain'
    ),
    pytest.param(
        dict(domain=_MULTI_DOMAIN, **_HTTP_MODE_COMMON_PARAM_PORTION),
        id='http_mode_multi_domain'
    ),
    pytest.param(
        dict(
            domain=_MULTI_DOMAIN, 
            working_directory='~/.pyacme/new', 
            **_HTTP_MODE_COMMON_PARAM_PORTION
        ),
        id='http_mode_multi_domain_new_wd'
    ),
]


@pytest.mark.httptest
@pytest.mark.docker_type('standalone')
@pytest.mark.host_entry(_DOMAIN+_MULTI_DOMAIN, '127.0.0.1')
@pytest.mark.usefixtures('setup_pebble_docker', 'root_host_entry')
class TestHttpMode:
    @pytest.mark.parametrize('params', http_mode_params)
    def test_http_mode(self, params):
        _common(params)
        # wait for a while if this is to be tested with test_pebble.py
        # time.sleep(5)


_STAGING_DOMAIN = ['test-staging.xn--jhqy4a5a064kimjf01df8e.host']
_STAGING_WILDCARD_DOMAIN = ['*.xn--jhqy4a5a064kimjf01df8e.host']
_STAGING_MULTI_DOMAIN = [
    'test-staging-1.xn--jhqy4a5a064kimjf01df8e.host',
    'test-staging-2.xn--jhqy4a5a064kimjf01df8e.host',
]
_DNS_MODE_COMMON_PARAM_PORTION = dict(
    contact=TEST_CONTACTS,
    country_code='UN',
    CA_entry=LETSENCRYPT_STAGING,
    mode='dns',
)

dns_mode_params = [
    pytest.param(
        dict(domain=_STAGING_DOMAIN, **_DNS_MODE_COMMON_PARAM_PORTION),
        id='dns_mode_single_domain'
    ),
    pytest.param(
        dict(domain=_STAGING_MULTI_DOMAIN, **_DNS_MODE_COMMON_PARAM_PORTION),
        id='dns_mode_multi_domain'
    ),
    pytest.param(
        dict(domain=_STAGING_WILDCARD_DOMAIN, **_DNS_MODE_COMMON_PARAM_PORTION),
        id='dns_mode_wildcard_domain'
    ),
]

@pytest.mark.dnstest
@pytest.mark.docker_type(None)
@pytest.mark.usefixtures('setup_pebble_docker')
class TestDNSMode:

    @pytest.mark.parametrize('params', dns_mode_params)
    def test_dns_mode(self, params, aliyun_access_key: Dict[str, str]):
        key_dict = dict(
            access_key=aliyun_access_key['access_key'],
            secret=aliyun_access_key['secret']
        )
        params = dict(**params, **key_dict)
        _common(params, ca='staging')
        time.sleep(5)