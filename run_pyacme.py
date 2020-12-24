"""
run the script with `sudo`
"""
from typing import Any, Dict, List
from pathlib import Path
from multiprocessing import Process
import time
import argparse

from pyacme.util import generate_rsa_privkey, get_keyAuthorization, parse_csr, \
                        run_http_server, jwk_factory
from pyacme.ACMEobj import ACMEAccount, ACMEAuthorization, ACMEOrder
from pyacme.actions import ACMEAccountActions
from pyacme.request import ACMERequestActions
from pyacme.dnsprovider.dispatch import DNS01ChallengeRespondHandler


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


def main_finalize(order, subject_names, cert_path, csr_priv_key_type):
    order.poll_order_state()
    if order.status == 'ready':
        if csr_priv_key_type.lower() == 'rsa':
            csr_privkey = generate_rsa_privkey(cert_path)
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


def main_poll_order_state(auths, poll_interval, poll_retry_count):
    # loop and poll the order state
    while poll_retry_count > 0:
        print('polling for authorization ...')
        for auth in auths:
            auth.poll_auth_state()
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


def main(domains: List[str], 
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
         chall_resp_server_port: int = 80) -> None:

    # wildcard domain only available for dns mode
    for d in domains:
        if '*' in d:
            mode = 'dns'
            break
    
    # set url for CA 
    ACMERequestActions.set_directory_url(CA_entry)
    ACMERequestActions.query_dir()
    req = ACMERequestActions()
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
        print('account created')
    elif acct._resp.status_code == 201:
        print('account existed and fetched')
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
            main_finalize(order, subject_names, cert_path, csr_priv_key_type)
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
            main_finalize(order, subject_names, cert_path, csr_priv_key_type)
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
        help='FDQN, international domain should use punycode; '
             'use multiple `-d` to provide more than one domains.'
    )
    parser.add_argument(
        '-c',
        '--contact',
        action='append',
        help="domain holder's email address for CA to send notification, "
             'use multiple `-c` to provide more than one contact email.'
    )
    parser.add_argument(
        '-C',
        '--country_code',
        required=True,
        help='two-digit country code, e.g. CN'
    )
    parser.add_argument(
        '--account_private_key',
        help='Optional, absolute path to a pem private key file. '
             'RSA key size must be larger than 2048 and multiple of 4'
    )
    parser.add_argument(
        '--not_before',
        help='Optional, a date time string, acme order will not be availabe '
             'before this time'
    )
    parser.add_argument(
        '--not_after',
        help='Optional, a date time string, acme order will not be availabe '
             'after this time'
    )
    parser.add_argument(
        '--cert_path',
        default='~/.pyacme',
        help='Optional, absolute path to where certificates will be saved, '
             r'default path is ~/.pyacme/{domain_name}/cert'
    )
    parser.add_argument(
        '--chall_path',
        help='Optional, absolute path to where http-01 challenge respond files '
             'will be served by a http server. default is '
             r'~/.pyacme/{domain_name}/chall_http'
    )
    parser.add_argument(
        '-m',
        '--mode',
        choices=['http', 'dns'],
        default='dns',
        help='Optional, decide how to complete acme challenge, default "dns"; '
             'root privilege needed for "http" mode'
    )
    parser.add_argument(
        '--dns_provider',
        choices=['aliyun'],
        default='aliyun',
        help='Optional, select one dnsprovider, default "aliyun"'
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
        action='append',
        help='Optional, for certain dnsproviders, pass "key=value" '
    )
    parser.add_argument(
        '--CA_entry',
        help='Optional, url to a CA /directory, default is letsencrypt prod'
    )
    parser.add_argument(
        '--poll_interval',
        type=float,
        default=5.0,
        help='Optional, seconds between each authorization poll, default 3.0'
    )
    parser.add_argument(
        '--poll_retry_count',
        type=int,
        default=24,
        help='Optional, total count of authorization poll retry, default 24'
    )
    parser.add_argument(
        '--csr_priv_key_type',
        choices=['rsa'],
        default='rsa',
        help='Optional, select key type to sign CSR, default "rsa"'
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
        default=80,
        help='Optional, the port used when responding to http-01 challenge; '
             'usually on port 80'
    )
    args = parser.parse_args()

    # test
    print(args)