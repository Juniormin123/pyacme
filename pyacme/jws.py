# from typing import Any, Dict, Optional
# import base64

# # import rsa
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.asymmetric import padding

# from pyacme.base import _JWSBase
# from pyacme.jwk import JWKRSA


from pyacme.jwk import JWSRS256
__all__ = ['JWSRS256']


# class JWSRS256(_JWSBase):
    
#     alg = 'RS256'
#     hash_method = 'SHA-256'
    
#     def __init__(self, 
#                  url: str, 
#                  nonce: str, 
#                  jwk: JWKRSA, 
#                  kid: str = '', 
#                  payload: Dict[str, Any] = dict()):
#         # self.jwk: JWKRSA
#         if not isinstance(jwk, JWKRSA):
#             raise TypeError(
#                 f'jwk type "{type(jwk)}" not compatible with {self.alg}'
#             )
#         super().__init__(self.alg, url, nonce, payload, jwk, kid)
    
#     def sign(self) -> None:
#         self.jwk: JWKRSA
#         sign_input = self.get_sign_input()
#         # sig = rsa.sign(sign_input, self.jwk.priv_key, self.hash_method)
#         sig = self.jwk.priv_key.sign(
#             data=sign_input,
#             # PKCS padding for `RS256` signature
#             # see https://tools.ietf.org/html/rfc7518#section-3.3
#             padding=padding.PKCS1v15(),
#             algorithm=hashes.SHA256()
#         )
#         self.signature = str(
#             base64.urlsafe_b64encode(sig).strip(b'='), encoding='utf-8'
#         )
#         self.post_body['signature'] = self.signature