from abc import ABCMeta, abstractmethod


class _DNSProviderBase(metaclass=ABCMeta):

    def __init__(self, access_key: str, secret: str, *args, **kwargs) -> None:
        pass

    @abstractmethod
    def add_txt_record(self, 
                       identifier: str, 
                       value: str, 
                       *args, 
                       **kwargs) -> None:
        pass

    @abstractmethod
    def clear_dns_record(self, *args, **kwargs) -> None:
        pass