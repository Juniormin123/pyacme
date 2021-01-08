from typing import List, Type
import logging

from ..ACMEobj import ACMEOrder, ACMEAuthorization
from ..util import get_dns_chall_txt_record
from .dnsproviderbase import _DNSProviderBase
from . import aliyun


logger = logging.getLogger(__name__)
info = logger.info
debug = logger.debug


class DNS01ChallengeRespondHandler:
    """
    use `eval(dnsprovider.Handler)` to get a dns handler class; to add more
    dns providers, name the new provider module using name that will be added 
    to attribute `supported_provider`, and create `Handler` class by 
    inheriting `dnsproviderbase._DNSProviderBase`.
    """

    supported_provider = ['aliyun']

    def __init__(self, 
                 order_obj: ACMEOrder,
                 dnsprovider: str,
                 access_key: str,
                 secret: str,
                 **kwargs):
        if not dnsprovider in self.supported_provider:
            raise ValueError(f'dnsprovider {dnsprovider} not supported')
        self.order_obj = order_obj
        handler_cls: Type[_DNSProviderBase] = eval(f'{dnsprovider}.Handler')
        self.handler = handler_cls(access_key, secret, **kwargs)
    
    def dns_chall_respond(self) -> List[ACMEAuthorization]:
        """add dns-01 respond to selected dns provider"""
        for auth in self.order_obj.auth_objs:
            if auth.chall_dns.status == 'valid':
                info(f'challenge for {auth.identifier_value} is already valid')
                continue
            value = get_dns_chall_txt_record(
                token=auth.chall_dns.token,
                jwk=self.order_obj.related_acct.jwk_obj
            )
            self.handler.add_txt_record(auth.identifier_value, value)
            auth.chall_dns.respond()
            info(f'respond to dns challenge for {auth.identifier_value}')
        return self.order_obj.auth_objs
    
    def clear_dns_record(self) -> None:
        self.handler.clear_dns_record()
