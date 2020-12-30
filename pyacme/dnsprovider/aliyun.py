"""
Install the following package:
`pip install aliyun-python-sdk-core`
`pip install aliyun-python-sdk-alidns`
"""

import json
from pyacme.ACMEobj import ACMEAuthorization

from aliyunsdkcore.client import AcsClient
from aliyunsdkcore.acs_exception.exceptions import ClientException
from aliyunsdkcore.acs_exception.exceptions import ServerException
from aliyunsdkalidns.request.v20150109.AddDomainRecordRequest \
    import AddDomainRecordRequest
from aliyunsdkalidns.request.v20150109.DescribeDomainRecordInfoRequest \
    import DescribeDomainRecordInfoRequest
from aliyunsdkalidns.request.v20150109.DeleteDomainRecordRequest \
    import DeleteDomainRecordRequest


def create_client(access_key: str, secret: str, r = 'cn-hangzhou') -> AcsClient:
    """
    provide access key, secret, return client object; key and secret 
    usually from aliyun RAM; region uses default value `'cn-hangzhou'`
    """
    return AcsClient(access_key, secret, r)


def add_dns_txt_record(client: AcsClient, 
                       domain: str, rr: str, value: str) -> dict:
    """
    `domain`: the literal domain string, no punycode used;

    `rr`: fill in `"_acme-challenge"`;

    `value`: fill in dns-01 challenge response text;

    upon success record addition, return `RecordId` like the follwing:
    ```
    {'RequestId': 'EF1FA305-8410-48EC-A599-C0F70B2D66B1',
     'RecordId': '20963244238718976'}
    ```
    the record id will be used for later record removal
    """
    domain_split = domain.split('.')
    if len(domain_split) > 2:
        # handle passed in domain like 'test.xn--jhqy4a5a064kimjf01df8e.host'
        sub, primary = '.'.join(domain_split[:-2]), '.'.join(domain_split[-2:])
        rr = rr + '.' + sub
    else:
        sub = ''
        primary = domain

    # TODO proper log
    print(f'add dns record {rr=} {sub=} {primary=} {value=}')

    request = AddDomainRecordRequest()
    request.set_accept_format('json')
    request.set_DomainName(primary)
    request.set_RR(rr)
    request.set_Value(value)
    request.set_Type("TXT")
    response = client.do_action_with_exception(request)
    return json.loads(str(response, encoding='utf-8'))


def query_domain_record_by_id(client: AcsClient, record_id: str) -> dict:
    request = DescribeDomainRecordInfoRequest()
    request.set_accept_format('json')
    request.set_RecordId(record_id)
    response = client.do_action_with_exception(request)
    return json.loads(str(response, encoding='utf-8'))


def del_domain_record_by_id(client: AcsClient, record_id: str) -> dict:
    request = DeleteDomainRecordRequest()
    request.set_accept_format('json')
    request.set_RecordId(record_id)
    response = client.do_action_with_exception(request)
    return json.loads(str(response, encoding='utf-8'))
