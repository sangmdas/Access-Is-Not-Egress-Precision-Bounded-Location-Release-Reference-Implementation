from __future__ import annotations
import base64, hashlib, hmac
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from .canonical import canonical_bytes

def b64e(b:bytes)->str: return base64.urlsafe_b64encode(b).decode().rstrip('=')
def b64d(s:str)->bytes: return base64.urlsafe_b64decode(s + '='*((4-len(s)%4)%4))

class Signer:
    algorithm: str
    key_id: str
    def sign(self, obj)->str: raise NotImplementedError
    def verify(self, obj, signature:str)->bool: raise NotImplementedError

class Ed25519Signer(Signer):
    algorithm='Ed25519'
    def __init__(self, private_key=None, public_key=None, key_id='ped-ed25519-1'):
        self.key_id=key_id
        self._private=private_key or (None if public_key else Ed25519PrivateKey.generate())
        self._public=public_key or self._private.public_key()
    def sign(self,obj)->str:
        if not self._private: raise ValueError('verification-only signer')
        return b64e(self._private.sign(canonical_bytes(obj)))
    def verify(self,obj,signature)->bool:
        try: self._public.verify(b64d(signature), canonical_bytes(obj)); return True
        except Exception: return False
    def verifier(self): return Ed25519Signer(public_key=self._public, key_id=self.key_id)

class HMACSigner(Signer):
    algorithm='HMAC-SHA256'
    def __init__(self, secret=b'reference-only-hmac-key-change-me', key_id='ped-hmac-1'):
        self.secret=secret; self.key_id=key_id
    def sign(self,obj)->str: return b64e(hmac.new(self.secret, canonical_bytes(obj), hashlib.sha256).digest())
    def verify(self,obj,signature)->bool: return hmac.compare_digest(self.sign(obj), signature)
    def verifier(self): return HMACSigner(self.secret,self.key_id)
