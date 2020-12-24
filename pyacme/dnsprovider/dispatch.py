from typing import List

from ..ACMEobj import ACMEOrder, ACMEAuthorization
from ..util import get_dns_chall_txt_record
from . import aliyun


class DNS01ChallengeRespondHandler:

    supported_provider = ['aliyun']

    def __init__(self, order_obj: ACMEOrder,
                       dnsprovider: str,
                       access_key: str,
                       secret: str,
                       **kwargs):
        if not dnsprovider in self.supported_provider:
            raise ValueError(f'dnsprovider {dnsprovider} not supported')
        self.order_obj = order_obj
        self.dnsprovider = dnsprovider
        self.access_key = access_key
        self.secret = secret
        self.provider_specific_param = kwargs
    
    def dns_chall_respond(self) -> List[ACMEAuthorization]:
        """add dns-01 respond to selected dns provider"""
        for auth in self.order_obj.auth_objs:
            if auth.chall_dns.status == 'valid':
                print(f'challenge for {auth.identifier_value} is already valid')
                continue
            value = get_dns_chall_txt_record(
                token=auth.chall_dns.token,
                jwk=self.order_obj.related_acct.jwk_obj
            )
            self._add_txt_general(auth.identifier_value, value)
            auth.chall_dns.respond()
            print(f'respond to dns challenge for {auth.identifier_value}')
        return self.order_obj.auth_objs
    
    def clear_dns_record(self) -> None:
        if self.dnsprovider == 'aliyun':
            self._clear_dns_record_aliyun()
        # TODO other provider

    def _add_txt_general(self, identifier: str, value: str, *args, **kwargs):
        if self.dnsprovider == 'aliyun':
            self._add_txt_aliyun(identifier, value)
        # TODO other provider
    
    def _add_txt_aliyun(self, identifier: str, value: str):
        client = aliyun.create_client(self.access_key, self.secret)
        if "*" in identifier:
            # if wildcard domain, remove "*"
            identifier = identifier.split('*.', maxsplit=1)[1]
        # aliyun takes non-punycode domain, change punycode back to literal
        domain = bytes(identifier, encoding='utf-8').decode('idna')
        resp_dict = aliyun.add_dns_txt_record(
            client=client, 
            domain=domain,
            rr='_acme-challenge',
            value=value
        )
        self._aliyun_record_id = resp_dict['RecordId']
    
    def _clear_dns_record_aliyun(self):
        if hasattr(self, '_aliyun_record_id'):
            client = aliyun.create_client(self.access_key, self.secret)
            aliyun.del_domain_record_by_id(client, self._aliyun_record_id)
            print(f'aliyun dns record {self._aliyun_record_id} cleared')
        else:
            print('no aliyun dns record cleared')
