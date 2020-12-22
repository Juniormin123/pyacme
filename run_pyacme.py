"""
run the script with `sudo`
"""
from typing import Dict, List
from pathlib import Path
from multiprocessing import Process
import time

from pyacme.util import generate_rsa_privkey, get_keyAuthorization, \
                        run_http_server, jwk_factory
from pyacme.ACMEobj import ACMEAccount, ACMEAuthorization, ACMEOrder
from pyacme.actions import ACMEAccountActions
from pyacme.request import ACMERequestActions


def wait_for_server_stop(p: Process) -> None:
    while True:
        if not p.is_alive():
            break
        time.sleep(0.5)
    print('server stopped')


def http_chall(order_obj: ACMEOrder, 
               chall_path: str) -> List[ACMEAuthorization]:
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


def dns_chall(order_obj: ACMEOrder) -> List[ACMEAuthorization]:
    # TODO
    return order_obj.auth_objs


def main(domains: List[str], 
         contact: List[str],
         acct_priv_key: str, 
         not_before: str,
         not_after: str,
         subject_names: Dict[str, str],
         cert_path: str, 
         chall_path: str, 
         mode: str,
         CA_entry: str,
         poll_interval: float,
         poll_retry_count: int,
         csr_priv_key_type: str) -> None:
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

    # start http server
    server_p = Process(
        target=run_http_server,
        # args=(chall_path, 80),
        args=(chall_path, 5002),
        # daemon=True
    )
    server_p.start()

    try:
        if mode == 'http':
            auths = http_chall(order, chall_path=chall_path)
            print('http challenge responded')
        # elif mode == 'dns':
        #     pass
        else:
            raise ValueError(f'not supported mode {mode}')

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

        # do not stop server in `for else` above to avoid deadlock
        print('all authorizaitons valid, stopping server')
        server_p.terminate()
        
        # finalize order
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
        
        order.poll_order_state()
        if order.status == 'valid':
            order.download_certificate(cert_path)
            print(f'certificates download to {cert_path}')
        else:
            raise ValueError(f'order state "{order.status}" != "valid"')

        wait_for_server_stop(server_p)
        print('all done')

    except Exception as e:
        print('stopping server due to exception')
        server_p.terminate()
        wait_for_server_stop(server_p)
        raise e


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
    from pyacme.settings import LETSENCRYPT_STAGING

    main(
        domains=['xn--jhqy4a5a064kimjf01df8e.host'],
        contact=['mailto:min641366609@live.com'],
        acct_priv_key='./test/test_privkey.pem',
        not_before='',
        not_after='',
        subject_names={'C': 'CN', 'O': 'test Org'},
        cert_path='./test/.staging_cert_files',
        chall_path=str(Path('/home/min123/acme')),
        mode='http',
        CA_entry=LETSENCRYPT_STAGING,
        poll_interval=5,
        poll_retry_count=24,
        csr_priv_key_type='rsa'
    )