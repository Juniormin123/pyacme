![build](https://github.com/Juniormin123/pyacme/workflows/build/badge.svg)
[![codecov](https://codecov.io/gh/Juniormin123/pyacme/branch/master/graph/badge.svg?token=MONG2K39ZJ)](https://codecov.io/gh/Juniormin123/pyacme)
# pyacme
A simple ACME client written in python

## Install
```bash
pip install pyacme
```
or clone this repo and use `pip install .`

## Usage
### Acquire certificate using http mode
Apply for single domain certificate using simpleast http config, root privilege needed.
```bash
sudo pyacme -d example.com -c "mailto:test@mail.com" -C US --mode http
```

### Acquire certificate using dns mode
Apply for single domain certificate using simpleast dns config, which uses aliyun as dns provider, no root required.
```bash
pyacme -d example.com -c "mailto:test@mail.com" -C US -k KEY -s SECRET
```

### Invoke with `sudo`
If package pyacme is installed inside environment like `conda`, it may need to specify the python path:
```bash
# e.g. inside a conda env
sudo $(which python) -m pyacme -d example.com -c "mailto:test@mail.com" -C US --mode http
```

### Acquire SAN certificates
Use multiple `-d` to supply domains. When multiple domains supplied, the root domain should be the same.
```bash
pyacme -d example.com -d a.example.com -c "mailto:test@mail.com" -C US -k KEY -s SECRET
```
When domains like `"a.example.com", "b.example.com"` supplied like the following, the root domain `"example.com"` will also be added to the certificate and fill the `Common Name` field.
```bash
pyacme -d a.example.com -d b.example.com -c "mailto:test@mail.com" -C US -k KEY -s SECRET
```


## Options reference
### required arguments:
`-d, --domain str`
FDQN; international domain should use punycode; use multiple `-d` to provide more than one domains.
`-c, --contact str`
input domain holder's email address for CA to send notification, use multiple `-c` to provide more than one contact email. `mailto:` prefix must be included.
`-C, --country_code`
two-digit country code, e.g. CN

### optional arguments:
`-h, --help`    
show this help message and exit

`--csr_subjects str`    
key=value string to csr values besisdes C and CN, e.g. `"ST=State,L=Locality,O=test Org,emailAddres=test@email.org"`

`--account_private_key path`    
absolute path to a pem private key file. RSA key size must be larger than 2048 and multiple of 4

`--not_before str`    
a date time string, acme order will not be availabe before this time; *has no effect for now*

`--not_after str`    
a date time string, acme order will not be availabe after this time; *has no effect for now*

`-w, --working_directory path`    
dafault is `~/.pyacme` ; cert can be found at `working_directroy/cert`

`-m {http,dns}, --mode {http,dns}`    
decide how to complete acme challenges, default "dns"; root privilege needed for "http" mode

`--dnsprovider {aliyun}`    
select one dnsprovider, current support following providers `['aliyun']`, default provider aliyun

`-k, --access_key str`    
access key or token to dns provider, if mode is "dns", this option is required; if mode is "http", this option is omitted

`-s, --secret str`    
secret or token to dns provider, if mode is "dns", and dnsprovider is "aliyun" this option is required; if mode is "http", this option is omitted

`--dns_specifics str`    
for certain dnsproviders, pass string like `"key1=value1,key2=value2 ..."`

`--CA_entry url`   
url to a CA /directory, default is `https://acme-v02.api.letsencrypt.org/directory`

`--poll_interval float`    
seconds between each authorization poll, default 5.0

`--poll_retry_count int`    
total count of authorization poll retry, default 24

`--csr_priv_key_type {rsa, es256}`    
select key type to sign CSR, default "rsa", which is rsa 2048; ECDSA with SECP256R1 is supported

`--csr_priv_key_size int`    
Optional, key size of key that will sign CSR, default 2048

`--chall_resp_server_port int`    
the port used when responding to http-01 challenge; default on port 80, root previlige needed

`--no_ssl_verify`       
disable ssl certificate verification when requesting acme resources, default False

`--debug`    
set this option to output debug message

`--version`    
show program's version number and exit
