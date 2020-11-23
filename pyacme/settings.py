# url to acme server's /directory
LETSENCRYPT_PRODUCTION = "https://acme-v02.api.letsencrypt.org/directory"
LETSENCRYPT_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"

# run a test pebble server in docker
# https://github.com/letsencrypt/pebble

# to prevent client ssl error, append test/certs/pebble.minica.pem to python
# package `certifi` cacert.pem which is used by `requests`
# see https://github.com/letsencrypt/pebble/tree/master/test/certs
TEST_IP = "127.0.0.1"
TEST_PORT = 14000

PEBBLE_TEST = f"https://{TEST_IP}:{TEST_PORT}/dir"

# pebble challenge test server management interfaces
# see https://github.com/letsencrypt/pebble/tree/master/cmd/pebble-challtestsrv
CHALL_TEST_PORT = 8055

PEBBLE_CHALLTEST_HTTP01 = f"http://{TEST_IP}:{CHALL_TEST_PORT}/add-http01"
PEBBLE_CHALLTEST_HTTP01_DEL = f"http://{TEST_IP}:{CHALL_TEST_PORT}/del-http01"

PEBBLE_CHALLTEST_DNS01 = f"http://{TEST_IP}:{CHALL_TEST_PORT}/set-txt"
PEBBLE_CHALLTEST_DNS01_DEL = f"http://{TEST_IP}:{CHALL_TEST_PORT}/clear-txt"

PEBBLE_CHALLTEST_TLS01 = f"http://{TEST_IP}:{CHALL_TEST_PORT}/add-tlsalpn01"
PEBBLE_CHALLTEST_TLS01_DEL = f"http://{TEST_IP}:{CHALL_TEST_PORT}/del-tlsalpn01"