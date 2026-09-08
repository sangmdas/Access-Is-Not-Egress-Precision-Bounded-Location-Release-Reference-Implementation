from __future__ import annotations
import base64, hashlib, json
from datetime import datetime, timezone
from enum import Enum
from pydantic import BaseModel

def _normal(v):
    if isinstance(v, BaseModel):
        return _normal(v.model_dump(exclude_none=True))
    if isinstance(v, dict):
        return {str(k): _normal(v[k]) for k in sorted(v)}
    if isinstance(v, (list, tuple)):
        return [_normal(x) for x in v]
    if isinstance(v, datetime):
        if v.tzinfo is None: v=v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc).isoformat().replace('+00:00','Z')
    if isinstance(v, Enum): return v.value
    if isinstance(v, float):
        if v != v or v in (float('inf'), float('-inf')): raise ValueError('non-finite float')
        return v
    return v

def canonical_bytes(v) -> bytes:
    return json.dumps(_normal(v), ensure_ascii=False, sort_keys=True, separators=(',',':'), allow_nan=False).encode('utf-8')

def digest(v, algorithm='sha256') -> str:
    h=hashlib.new(algorithm); h.update(canonical_bytes(v)); return base64.urlsafe_b64encode(h.digest()).decode().rstrip('=')

def sha256_bytes(data: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip('=')
