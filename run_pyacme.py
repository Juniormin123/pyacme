"""
run the script with `sudo`
"""
from typing import Any, Dict, List
from pathlib import Path
from multiprocessing import Process
import time
import argparse

from pyacme.util import check_path, generate_rsa_privkey, \
                        get_keyAuthorization, \
                        main_param_parser, parse_csr, \
                        run_http_server, jwk_factory
from pyacme.ACMEobj import ACMEAccount, ACMEAuthorization, ACMEOrder
from pyacme.actions import ACMEAccountActions
from pyacme.request import ACMERequestActions
from pyacme.dnsprovider.dispatch import DNS01ChallengeRespondHandler
from pyacme.settings import *


def wait_for_server_stop(p: Process) -> None:
    while True:
        if not p.is_alive():
            break
        time.sleep(0.5)
    print('server stopped')


def http_chall(order_obj: ACMEOrder, 
               chall_path: str) -> List[ACMEAuthorization]:
    """
    create http-01 respond file in arg `chall_path`
    """
    base_path = Path(chall_path).absolute() / '.well-known' / 'acme-challenge'
    for auth in order_obj.auth_objs:
        if auth.chall_http.status == 'valid':
            print(f'challenge for {auth.identifier_value} is already valid')
            continue
        # create repond text for each auth http challenge
        chall_text = get_keyAuthorization(
            token=auth.chall_http.token,
            jwk=order_obj.related_acct.jwk_obj
        )
        with open(base_path/auth.chall_http.token, 'w') as f:
            f.write(chall_text)
        auth.chall_http.respond()
        print(f'respond to http challenge for {auth.identifier_value}')
    return order_obj.auth_objs


def main_finalize(order: ACMEOrder, 
                  subject_names: Dict[str, str], 
                  cert_path: str, 
                  csr_priv_key_type: int,
                  csr_priv_key_size: int):
    order.poll_order_state()
    if order.status == 'ready':
        if csr_priv_key_type.lower() == 'rsa':
            csr_privkey = generate_rsa_privkey(
                privkey_dir=cert_path,
                keysize=csr_priv_key_size,
                key_name=CSR_KEY_NAME
            )
        else:
            raise ValueError(
                f'not supported csr key type {csr_priv_key_type}'
            )
        order.finalize_order(
            privkey=csr_privkey,
            engine='cryptography',
            **subject_names
        )
        print('order finalized')
    else:
        raise ValueError(f'order state "{order.status}" != "ready"')


def main_poll_order_state(auths: List[ACMEAuthorization], 
                          poll_interval: float, 
                          poll_retry_count: int):
    # loop and poll the order state
    while poll_retry_count > 0:
        print('polling for authorization ...')
        for auth in auths:
            auth.poll_auth_state()
            if auth.status == 'invalid':
                raise ValueError(
                    f'authorization for domain {auth.identifier_value} invalid'
                )
            if auth.status != 'valid':
                break
        else:
            # here all auth valid, stop server
            break
        poll_retry_count -= 1
        time.sleep(poll_interval)


def main_download_cert(order, cert_path):
    order.poll_order_state()
    if order.status == 'valid':
        order.download_certificate(cert_path)
        print(f'certificates download to {cert_path}')
    else:
        raise ValueError(f'order state "{order.status}" != "valid"')


def main(*,
         domains: List[str], 
         contact: List[str],
         acct_priv_key: str, 
         not_before: str,
         not_after: str,
         subject_names: Dict[str, str],
         cert_path: str, 
         chall_path: str, 
         mode: str,
         dnsprovider: str,
         access_key: str,
         secret: str,
         dns_specifics: Dict[str, Any],
         CA_entry: str,
         poll_interval: float,
         poll_retry_count: int,
         csr_priv_key_type: str,
         csr_priv_key_size: int,
         chall_resp_server_port: int,
         no_ssl_verify: bool) -> None:

    if no_ssl_verify:
        ACMERequestActions.verify = False

    # set url for CA 
    ACMERequestActions.set_directory_url(CA_entry)
    ACMERequestActions.query_dir()
    req = ACMERequestActions()
    req.new_nonce()
    # init key object
    jwk = jwk_factory(acct_priv_key)
    # init acct action
    acct_action = ACMEAccountActions(req)
    acct = ACMEAccount.init_by_create(
        jwk=jwk,
        acct_actions=acct_action,
        contact=contact
    )
    if acct._resp.status_code == 200:
        print('account existed and fetched')
    elif acct._resp.status_code == 201:
        print('new account created')
    # create new order for domains
    order = acct.new_order(
        identifiers=domains,
        not_after=not_after,
        not_before=not_before
    )
    print(f'order created {domains}')


    if mode == 'http':
        # start http server
        server_p = Process(
            target=run_http_server,
            args=(chall_path, chall_resp_server_port),
            # daemon=True
        )
        server_p.start()
        try:
            auths = http_chall(order, chall_path=chall_path)
            print('http challenge responded')

            # loop and poll the order state
            main_poll_order_state(auths, poll_interval, poll_retry_count)

            # do not stop server in `for else` above to avoid deadlock
            print('all authorizaitons valid, stopping server')
            server_p.terminate()
            
            # finalize order
            main_finalize(
                order, subject_names, cert_path, 
                csr_priv_key_type, csr_priv_key_size
            )
            main_download_cert(order, cert_path)
            wait_for_server_stop(server_p)

            print('http mode all done')
        except Exception as e:
            print('stopping server due to exception')
            server_p.terminate()
            wait_for_server_stop(server_p)
            raise e
    
    elif mode == 'dns':
        handler = DNS01ChallengeRespondHandler(
            order_obj=order,
            dnsprovider=dnsprovider,
            access_key=access_key,
            secret=secret,
            **dns_specifics
        )
        try:
            auths = handler.dns_chall_respond()
            print('dns challenge responded')
            # loop and poll the order state
            main_poll_order_state(auths, poll_interval, poll_retry_count)
            print('all authorizaitons valid, clearing dns record')
            handler.clear_dns_record()
            # finalize order
            main_finalize(
                order, subject_names, cert_path, 
                csr_priv_key_type, csr_priv_key_size
            )
            main_download_cert(order, cert_path)
            
            print('dns mode all done')
        except Exception as e:
            print('removing dns record due to exception')
            handler.clear_dns_record()
            raise e
    else:
        raise ValueError(f'not supported mode {mode}')


if __name__ == '__main__':
    # test run with `sudo $(which python) run_pyacme.py`
    # main(
    #     # domains=['test.local'],
    #     domains=['xn--jhqy4a5a064kimjf01df8e.host'],
    #     contact=['mailto:min641366609@live.com'],
    #     acct_priv_key='./test/test_privkey.pem',
    #     not_before='',
    #     not_after='',
    #     subject_names={'C': 'CN', 'O': 'test Org'},
    #     cert_path='./test/.cert_files',
    #     chall_path=str(Path('/home/min123/acme')),
    #     mode='http',
    #     CA_entry='https://192.168.50.3:14000/dir',
    #     poll_interval=2,
    #     poll_retry_count=60,
    #     csr_priv_key_type='rsa'
    # )

    # test run with letsencrypt staing
    from pyacme.settings import LETSENCRYPT_STAGING, LETSENCRYPT_PRODUCTION

    # main(
    #     domains=['xn--jhqy4a5a064kimjf01df8e.host'],
    #     contact=['mailto:min641366609@live.com'],
    #     acct_priv_key='./test/test_privkey.pem',
    #     not_before='',
    #     not_after='',
    #     subject_names={'C': 'CN', 'ST': 'Hong Kong'},
    #     cert_path='./test/.staging_cert_files',
    #     chall_path=str(Path('/home/min123/acme')),
    #     mode='http',
    #     CA_entry=LETSENCRYPT_STAGING,
    #     poll_interval=5,
    #     poll_retry_count=24,
    #     csr_priv_key_type='rsa'
    # )

    # production test
    # main(
    #     domains=['xn--uvz335a.xn--jhqy4a5a064kimjf01df8e.host'],
    #     contact=['mailto:min641366609@live.com'],
    #     acct_priv_key='./test/test_privkey.pem',
    #     not_before='',
    #     not_after='',
    #     subject_names={'C': 'CN', 'ST': 'Hong Kong'},
    #     cert_path='./test/.prod_cert_files',
    #     chall_path=str(Path('/home/min123/acme')),
    #     mode='http',
    #     CA_entry=LETSENCRYPT_PRODUCTION,
    #     poll_interval=5,
    #     poll_retry_count=24,
    #     csr_priv_key_type='rsa'
    # )

    # test for wildcard domain and dns method
    # main(
    #     domains=['*.xn--jhqy4a5a064kimjf01df8e.host'],
    #     contact=['mailto:min641366609@live.com'],
    #     acct_priv_key='./test/test_privkey.pem',
    #     not_before='',
    #     not_after='',
    #     subject_names={'C': 'CN', 'ST': 'Hong Kong'},
    #     cert_path='./test/.prod_cert_files',
    #     chall_path=str(Path('/home/min123/acme')),
    #     mode='dns',
    #     CA_entry=LETSENCRYPT_STAGING,
    #     poll_interval=5,
    #     poll_retry_count=24,
    #     dnsprovider='aliyun',
    #     # input key mannually
    #     access_key='',
    #     secret='',
    #     dns_specifics=dict(),
    #     csr_priv_key_type='rsa'
    # )
    parser = argparse.ArgumentParser(
        description='A simple acme client written in python'
    )
    parser.add_argument(
        '-d',
        '--domain',
        required=True,
        action='append',
        help='Required, FDQN, international domain should use punycode; '
             'use multiple `-d` to provide more than one domains.'
    )
    parser.add_argument(
        '-c',
        '--contact',
        action='append',
        help="Optional if acctount exists in workding directory; "
             "domain holder's email address for CA to send "
             "notification, use multiple `-c` to provide more than one "
             "contact email."
    )
    parser.add_argument(
        '-C',
        '--country_code',
        required=True,
        help='Required, two-digit country code, e.g. CN'
    )
    parser.add_argument(
        '--csr_subjects',
        help='key=value string to csr values besisdes C and CN, '
             'e.g. "ST=State,L=Locality,O=test Org,emailAddres=test@email.org"'
    )
    parser.add_argument(
        '--account_private_key',
        help='absolute path to a pem private key file. '
             'RSA key size must be larger than 2048 and multiple of 4'
    )
    parser.add_argument(
        '--not_before',
        help='a date time string, acme order will not be availabe '
             'before this time'
    )
    parser.add_argument(
        '--not_after',
        help='a date time string, acme order will not be availabe '
             'after this time'
    )
    # parser.add_argument(
    #     '--cert_path',
    #     default='~/.pyacme',
    #     help='Optional, absolute path to where certificates will be saved, '
    #          r'default path is ~/.pyacme/{domain_name}/cert'
    # )
    # parser.add_argument(
    #     '--chall_path',
    #     help='Optional, absolute path to where http-01 challenge respond files '
    #          'will be served by a http server. default is '
    #          r'~/.pyacme/{domain_name}/chall_http'
    # )
    parser.add_argument(
        '-w',
        '--working_directory',
        default=WD_DEFAULT,
        help=f'dafault is {WD_DEFAULT} ; '
             f'cert can be found at working_directroy/{WD_CERT}'
    )
    parser.add_argument(
        '-m',
        '--mode',
        choices=MODES_SUPPORTED,
        default=MODES_DEFAULT,
        help='decide how to complete acme challenge, '
             f'default "{MODES_DEFAULT}"; '
             'root privilege needed for "http" mode'
    )
    parser.add_argument(
        '--dnsprovider',
        choices=DNS_PROVIDERS,
        default=DNS_DEFAULT_PROVIDER,
        help='select one dnsprovider, '
             f'current support following providers {DNS_PROVIDERS}, '
             f'default provider {DNS_DEFAULT_PROVIDER}'
    )
    parser.add_argument(
        '-k',
        '--access_key',
        help='access key or token to dns provider, if mode is "dns", this '
             'option is required; if mode is "http", this option is omitted'
    )
    parser.add_argument(
        '-s',
        '--secret',
        help='secret or token to dns provider, if mode is "dns", and '
             'dnsprovider is "aliyun" this option is required; '
             'if mode is "http", this option is omitted'
    )
    parser.add_argument(
        '--dns_specifics',
        help='for certain dnsproviders, pass string like '
             '"key1=value1,key2=value2 ..."'
    )
    parser.add_argument(
        '--CA_entry',
        help=f'url to a CA /directory, default is {LETSENCRYPT_PRODUCTION}'
    )
    parser.add_argument(
        '--poll_interval',
        type=float,
        default=REQ_POLL_INTERVAL,
        help='Optional, seconds between each authorization poll, '
             f'default {REQ_POLL_INTERVAL}'
    )
    parser.add_argument(
        '--poll_retry_count',
        type=int,
        default=REQ_POLL_RETRY_COUNT,
        help='total count of authorization poll retry, '
             f'default {REQ_POLL_RETRY_COUNT}'
    )
    parser.add_argument(
        '--csr_priv_key_type',
        choices=['rsa'],
        default='rsa',
        help='select key type to sign CSR, default "rsa"'
    )
    parser.add_argument(
        '--csr_priv_key_size',
        type=int,
        default=2048,
        help='Optional, key size of key that will sign CSR, default 2048'
    )
    parser.add_argument(
        '--chall_resp_server_port',
        type=int,
        default=HTTP_SERVING_PORT,
        help='the port used when responding to http-01 challenge; '
             f'default on port {HTTP_SERVING_PORT}, root previlige needed'
    )
    parser.add_argument(
        '--no_ssl_verify',
        action='store_true',
        help='disable ssl certificate verification when requesting acme '
             'resources, default False'
    )
    args = parser.parse_args()

    # test
    print(args)

    param_dict = main_param_parser(args)
    # test
    print(param_dict)

    main(**param_dict)
