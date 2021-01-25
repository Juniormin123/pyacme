# url to acme server's /directory
LETSENCRYPT_PRODUCTION = "https://acme-v02.api.letsencrypt.org/directory"
LETSENCRYPT_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"

# working directory settings
WD_DEFAULT = '~/.pyacme'
WD_HTTP01 = 'chall_http'
WD_CERT = 'cert'
WD_ACCT = 'acct'
WD_BAK = 'backup'

# keys related
KEY_ACCT_KEYTYPE = ['rsa', 'es256']
KEY_ACCT_KEYTYPE_DEFAULT = 'rsa'
KEY_ACCT = 'acct.pem'
KEY_SIZE = 2048

# certificate related
CERT_NAME = 'cert.pem'
CERT_CHAIN = 'chain.pem'
CERT_FULLCHAIN = 'fullchain.pem'

# challenge related
MODES_SUPPORTED = ['http', 'dns']
MODES_DEFAULT = 'dns'

# HTTP01
HTTP_SERVING_PORT = 80

# DNS01 and dns provider
DNS_PROVIDERS = ['aliyun']
DNS_DEFAULT_PROVIDER = 'aliyun'

# CSR related
CSR_SUPPORTED_KEY_TYPE = ['rsa', 'es256']
CSR_DEFAULT_KEY_TYPE = 'rsa'
CSR_RSA_PRIVATE_KEY_SIZE = 2048
CSR_KEY_NAME = 'certkey.key'

# request related
REQ_POLL_INTERVAL = 5.0            # seconds
REQ_POLL_RETRY_COUNT: int = 24

# backup related
BAK_TIME_FMT = '%Y_%m_%d_%H_%M_%S'
BAK_DEFAULT_PATTERN = 'bak_{date_time}.zip'

# logging
LOG_LEVEL = 20    # INFO
LOG_FMT = '[{asctime!s}][{name!s}][{levelname!s}] {msg}'
LOG_DEBUG_FMT = '[{asctime!s}][{name!s}][{levelname!s}] {funcName!s}: {msg}'