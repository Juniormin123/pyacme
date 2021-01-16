![build](https://github.com/Juniormin123/pyacme/workflows/pyacme-ci/badge.svg)
# pyacme
A simple ACME client written in python

## Usage
### acquire certificate using http mode
Apply for single domain certificate using simpleast http config, root privilege needed.
```bash
sudo pyacme -d example.com -c "mailto:test@mail.com" -C US --mode http
```

### acquire certificate using dns mode
Apply for single domain certificate using simpleast dns config, which uses aliyun as dns provider, no root required.
```bash
pyacme -d example.com -c "mailto:test@mail.com" -C US --k KEY --s SECRET
```

### acquire SAN certificates
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
`-d, --domain`
FDQN; international domain should use punycode; use multiple `-d` to provide more than one domains.
`-c, --contact`
input domain holder's email address for CA to send notification, use multiple `-c` to provide more than one contact email. `mailto:` prefix should be included.
`-C, --country_code`
two-digit country code, e.g. CN

### optional arguments:
`-h, --help`    
show this help message and exit

`--csr_subjects`    
key=value string to csr values besisdes C and CN, e.g. `"ST=State,L=Locality,O=test Org,emailAddres=test@email.org"`

`--account_private_key`    
absolute path to a pem private key file. RSA key size must be larger than 2048 and multiple of 4

`--not_before`    
a date time string, acme order will not be availabe before this time; *has no effect for now*

`--not_after NOT_AFTER`    
a date time string, acme order will not be availabe after this time; *has no effect for now*

`-w, --working_directory`    
dafault is `~/.pyacme` ; cert can be found at `working_directroy/cert`

`-m {http,dns}, --mode {http,dns}`    
decide how to complete acme challenges, default "dns"; root privilege needed for "http" mode

`--dnsprovider {aliyun}`    
select one dnsprovider, current support following providers `['aliyun']`, default provider aliyun

`-k, --access_key`    
access key or token to dns provider, if mode is "dns", this option is required; if mode is "http", this option is omitted

`-s, --secret`    
secret or token to dns provider, if mode is "dns", and dnsprovider is "aliyun" this option is required; if mode is "http", this option is omitted

`--dns_specifics`    
for certain dnsproviders, pass string like `"key1=value1,key2=value2 ..."`

`--CA_entry CA_ENTRY`   
url to a CA /directory, default is `https://acme-v02.api.letsencrypt.org/directory`

`--poll_interval`    
seconds between each authorization poll, default 5.0

`--poll_retry_count`    
total count of authorization poll retry, default 24

`--csr_priv_key_type {rsa}`    
select key type to sign CSR, default "rsa"

`--csr_priv_key_size`    
Optional, key size of key that will sign CSR, default 2048

`--chall_resp_server_port`    
the port used when responding to http-01 challenge; default on port 80, root previlige needed

`--no_ssl_verify`       
disable ssl certificate verification when requesting acme resources, default False

`--debug`    
set this option to output debug message

`--version`    
show program's version number and exit