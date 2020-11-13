# url to acme server's /directory
LETSENCRYPT_PRODUCTION = "https://acme-v02.api.letsencrypt.org/directory"
LETSENCRYPT_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"

# run a test pebble server in docker
# https://github.com/letsencrypt/pebble

# to prevent client ssl error, append test/certs/pebble.minica.pem to python
# package `certifi` cacert.pem which is used by `requests`
# see https://github.com/letsencrypt/pebble/tree/master/test/certs
PEBBLE_TEST = "https://127.0.0.1:14000/dir"