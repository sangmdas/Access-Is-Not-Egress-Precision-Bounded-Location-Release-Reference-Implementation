from __future__ import annotations
import math, hashlib
from .models import RawLocation, Precision

_BASE32='0123456789bcdefghjkmnpqrstuvwxyz'
def geohash_encode(lat,lon,precision=6):
    lat_i=[-90.0,90.0]; lon_i=[-180.0,180.0]; even=True; bit=0; ch=0; out=[]; bits=[16,8,4,2,1]
    while len(out)<precision:
        rng=lon_i if even else lat_i; val=lon if even else lat
        mid=sum(rng)/2
        if val>=mid: ch|=bits[bit]; rng[0]=mid
        else: rng[1]=mid
        even=not even
        if bit<4: bit+=1
        else: out.append(_BASE32[ch]); bit=0; ch=0
    return ''.join(out)

def transform_location(raw:RawLocation,precision:Precision):
    if precision==Precision.EXACT:
        return {'latitude':raw.latitude,'longitude':raw.longitude,'accuracy_meters':raw.accuracy_meters}
    if precision==Precision.METER_10:
        return {'latitude':round(raw.latitude,4),'longitude':round(raw.longitude,4),'precision_class':'METER_10'}
    if precision==Precision.METER_100:
        return {'latitude':round(raw.latitude,3),'longitude':round(raw.longitude,3),'precision_class':'METER_100'}
    if precision==Precision.GRID:
        return {'grid_id':f"g:{math.floor(raw.latitude*100)/100:.2f}:{math.floor(raw.longitude*100)/100:.2f}"}
    if precision==Precision.GEOHASH:
        return {'geohash':geohash_encode(raw.latitude,raw.longitude,5)}
    if precision==Precision.CITY:
        if not raw.city: raise ValueError('city label unavailable')
        return {'city':raw.city, **({'region':raw.region} if raw.region else {}), **({'country':raw.country} if raw.country else {})}
    if precision==Precision.REGION:
        if not raw.region: raise ValueError('region label unavailable')
        return {'region':raw.region, **({'country':raw.country} if raw.country else {})}
    if precision==Precision.COUNTRY:
        if not raw.country: raise ValueError('country label unavailable')
        return {'country':raw.country}
    return {}

def randomized_100m(raw:RawLocation,nonce:str):
    """Deterministic demo jitter for reproducible tests; NOT a differential-privacy mechanism."""
    h=hashlib.sha256(nonce.encode()).digest(); a=int.from_bytes(h[:4],'big')/2**32; b=int.from_bytes(h[4:8],'big')/2**32
    # roughly +/-50 m; illustrative only
    lat_j=(a-.5)*0.0009; lon_j=(b-.5)*0.0009/max(math.cos(math.radians(raw.latitude)),0.2)
    return {'latitude':round(raw.latitude+lat_j,4),'longitude':round(raw.longitude+lon_j,4),'precision_class':'METER_100','randomized':True}
