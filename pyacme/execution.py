from typing import Any, Dict, List, Sequence
from pathlib import Path
from multiprocessing import Process
import time
import argparse
import logging

from pyacme.util import generate_privkey, get_keyAuthorization, \
                        main_param_parser, run_http_server, jwk_factory
from pyacme.ACMEobj import ACMEAccount, ACMEAuthorization, ACMEOrder
from pyacme.actions import ACMEAccountActions
from pyacme.request import ACMERequestActions
from pyacme.dnsprovider.dispatch import DNS01ChallengeRespondHandler
from pyacme.settings import *


logger = logging.getLogger(__name__)
debug = logger.debug
info = logger.info


def wait_for_server_stop(p: Process) -> None:
    # after p is terminate()
    p.join()
    while True:
        if not p.is_alive():
            break
        time.sleep(0.5)
    info(f'server on process {p.pid} stopped')


def http_chall(order_obj: ACMEOrder, 
               chall_path: str) -> List[ACMEAuthorization]:
    """
    create http-01 respond file in arg `chall_path`
    """
    base_path = Path(chall_path).absolute() / '.well-known' / 'acme-challenge'
    for auth in order_obj.auth_objs:
        if auth.chall_http.status == 'valid':
            info(f'challenge for {auth.identifier_value} is already valid')
            continue
        # create repond text for each auth http challenge
        chall_text = get_keyAuthorization(
            token=auth.chall_http.token,
            jwk=order_obj.related_acct.jwk_obj
        )
        with open(base_path/auth.chall_http.token, 'w') as f:
            f.write(chall_text)
        auth.chall_http.respond()
        info(f'respond to http challenge for {auth.identifier_value}')
    return order_obj.auth_objs


def main_finalize(order: ACMEOrder, 
                  subject_names: Dict[str, str], 
                  cert_path: str, 
                  csr_priv_key_type: str,
                  csr_priv_key_size: int):
    order.poll_order_state()
    if order.status == 'ready':
        # if csr_priv_key_type.lower() == 'rsa':
        #     csr_privkey = generate_rsa_privkey(
        #         privkey_dir=cert_path,
        #         keysize=csr_priv_key_size,
        #         key_name=CSR_KEY_NAME
        #     )
        # else:
        #     raise ValueError(
        #         f'not supported csr key type {csr_priv_key_type}'
        #     )
        csr_privkey = generate_privkey(
            key_type=csr_priv_key_type,
            privkey_dir=cert_path,
            key_name=CSR_KEY_NAME,
            key_size=csr_priv_key_size
        )
        order.finalize_order(
            privkey=csr_privkey,
            **subject_names
        )
        debug(str(order))
        info('order finalized')
    else:
        raise ValueError(f'order state "{order.status}" != "ready"')


def main_poll_order_state(auths: List[ACMEAuthorization], 
                          poll_interval: float, 
                          poll_retry_count: int):
    # loop and poll the order state
    while poll_retry_count > 0:
        info('polling for authorization ...')
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


def main_download_cert(order: ACMEOrder, cert_path):
    order.poll_order_state()
    if order.status == 'valid':
        order.download_certificate(cert_path)
        debug(str(order))
        info(f'certificates download to {cert_path}')
    else:
        raise ValueError(f'order state "{order.status}" != "valid"')


def main_add_args(args: Sequence = []) -> argparse.Namespace:
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
        help="input domain holder's email address for CA to send "
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
        default=LETSENCRYPT_PRODUCTION,
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
        # choices=['rsa'],
        choices=CSR_SUPPORTED_KEY_TYPE,
        default=CSR_DEFAULT_KEY_TYPE,
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
    parser.add_argument(
        '--acct_key_type',
        choices=KEY_ACCT_KEYTYPE,
        default=KEY_ACCT_KEYTYPE_DEFAULT,
        help='decide acme server private key type, default '
             f'{KEY_ACCT_KEYTYPE_DEFAULT}'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='set this option to output debug message'
    )

    from pyacme import __version__
    parser.add_argument(
        '--version',
        action='version',
        version='%(prog)s ' + f'{__version__}'
    )
    if args:
        parsed_args = parser.parse_args(args)
    else:
        parsed_args = parser.parse_args()
    return parsed_args


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
    debug(str(acct))
    if acct._resp.status_code == 200:
        info('account existed and fetched')
    elif acct._resp.status_code == 201:
        info('new account created')
    # create new order for domains
    order = acct.new_order(
        identifiers=domains,
        not_after=not_after,
        not_before=not_before
    )
    debug(str(order))
    info(f'order created {domains}')


    if mode == 'http':
        # start http server
        server_p = Process(
            target=run_http_server,
            args=(chall_path, chall_resp_server_port),
            # daemon=True
        )
        server_p.start()

        # TODO 
        # waiting is needed when pytest-cov is enabled, reason unknown
        time.sleep(1)

        try:
            auths = http_chall(order, chall_path=chall_path)
            for a in auths: debug(str(a))
            info('http challenge responded')

            # loop and poll the order state
            main_poll_order_state(auths, poll_interval, poll_retry_count)

            # do not stop server in `for else` above to avoid deadlock
            info('all authorizaitons valid, stopping server')
            server_p.terminate()
            
            # finalize order
            main_finalize(
                order, subject_names, cert_path, 
                csr_priv_key_type, csr_priv_key_size
            )
            main_download_cert(order, cert_path)
            wait_for_server_stop(server_p)

            info('http mode all done')
        except Exception as e:
            logger.warning('stopping server due to exception')
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
            info('dns challenge responded')
            # loop and poll the order state
            main_poll_order_state(auths, poll_interval, poll_retry_count)
            info('all authorizaitons valid, clearing dns record')
            handler.clear_dns_record()
            # finalize order
            main_finalize(
                order, subject_names, cert_path, 
                csr_priv_key_type, csr_priv_key_size
            )
            main_download_cert(order, cert_path)
            
            info('dns mode all done')
        except Exception as e:
            logger.warning('removing dns record due to exception')
            handler.clear_dns_record()
            raise e
    else:
        raise ValueError(f'not supported mode {mode}')


def main_entry_point():
    args = main_add_args()
    debug(args)
    param_dict = main_param_parser(args)
    debug(param_dict)
    main(**param_dict)


def main_entry_point_test(p: Sequence):
    args = main_add_args(p)
    debug(args)
    param_dict = main_param_parser(args)
    debug(param_dict)
    main(**param_dict)