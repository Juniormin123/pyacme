from pathlib import Path


# run a test pebble server in docker
# https://github.com/letsencrypt/pebble

# to prevent client ssl error, append test/certs/pebble.minica.pem to python
# package `certifi` cacert.pem which is used by `requests` or
# set "verify=False" when using requests
# see https://github.com/letsencrypt/pebble/tree/master/test/certs
VERIFY_SSL = False

TEST_IP = "127.0.0.1"
TEST_PORT = 14000

PEBBLE_TEST = f"https://{TEST_IP}:{TEST_PORT}/dir"
 
# use pebble verify port
PY_HTTPSERVER_PORT = '5002'

# pebble challenge test server management interfaces
# see https://github.com/letsencrypt/pebble/tree/master/cmd/pebble-challtestsrv
CHALL_TEST_PORT = 8055

PEBBLE_CHALLTEST_DNS_A = f"http://{TEST_IP}:{CHALL_TEST_PORT}/add-a"
PEBBLE_CHALLTEST_DNS_A_DEL = f"http://{TEST_IP}:{CHALL_TEST_PORT}/clear-a"

PEBBLE_CHALLTEST_HTTP01 = f"http://{TEST_IP}:{CHALL_TEST_PORT}/add-http01"
PEBBLE_CHALLTEST_HTTP01_DEL = f"http://{TEST_IP}:{CHALL_TEST_PORT}/del-http01"

PEBBLE_CHALLTEST_DNS01 = f"http://{TEST_IP}:{CHALL_TEST_PORT}/set-txt"
PEBBLE_CHALLTEST_DNS01_DEL = f"http://{TEST_IP}:{CHALL_TEST_PORT}/clear-txt"

PEBBLE_CHALLTEST_TLS01 = f"http://{TEST_IP}:{CHALL_TEST_PORT}/add-tlsalpn01"
PEBBLE_CHALLTEST_TLS01_DEL = f"http://{TEST_IP}:{CHALL_TEST_PORT}/del-tlsalpn01"

# name for pebble and challtest container
PEBBLE_DOCKER_FILE = \
    Path(__file__).parents[2].absolute() / 'pebble' / 'docker-compose.yml'
PEBBLE_CONTAINER = 'pebble_pebble_1'
PEBBLE_CHALLTEST_CONTAINER = 'pebble_challtestsrv_1'

# staging root ca
STAGING_ROOT_CA = 'https://letsencrypt.org/certs/fakelerootx1.pem'

## test
# print(Path(__file__).parents[2])
# print(__file__)
# print(PEBBLE_DOCKER_FILE)