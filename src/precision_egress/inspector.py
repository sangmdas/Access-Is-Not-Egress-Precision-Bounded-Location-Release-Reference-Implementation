from __future__ import annotations
from .models import Precision

LAT_KEYS={'lat','latitude','gps_lat','gpslatitude','x_lat'}
LON_KEYS={'lon','lng','longitude','gps_lon','gpslongitude','x_lon'}
EXACT_CONTAINER_KEYS={'coordinates','gps','location_coordinates'}
METER10_KEYS={'accuracy_meters','horizontal_accuracy'}
GEOHASH_KEYS={'geohash'}
GRID_KEYS={'grid_id','grid','cell_id'}
CITY_KEYS={'city','locality','town'}
REGION_KEYS={'region','state','province'}
COUNTRY_KEYS={'country','country_code'}

def _walk(obj,path=''):
    if isinstance(obj,dict):
        for k,v in obj.items():
            yield str(k).lower(),v,f'{path}.{k}' if path else str(k)
            yield from _walk(v,f'{path}.{k}' if path else str(k))
    elif isinstance(obj,list):
        for i,v in enumerate(obj): yield from _walk(v,f'{path}[{i}]')

def _coordinate_values(fields):
    lat=[]; lon=[]; containers=[]
    for k,v,path in _walk(fields):
        if k in LAT_KEYS and isinstance(v,(int,float)): lat.append((float(v),path))
        if k in LON_KEYS and isinstance(v,(int,float)): lon.append((float(v),path))
        if k in EXACT_CONTAINER_KEYS: containers.append(path)
    return lat,lon,containers

def _coarse_coordinate_class(fields):
    """Validate demonstration meter-class encoding instead of trusting its label."""
    pc=fields.get('precision_class') if isinstance(fields,dict) else None
    lat,lon,containers=_coordinate_values(fields)
    if containers: return Precision.EXACT,[f'body:{p}' for p in containers]
    if not lat and not lon: return None,[]
    if not lat or not lon: return Precision.EXACT,[f'body:{p}' for _,p in lat+lon]
    vals=[x for x,_ in lat+lon]
    if pc=='METER_100' and all(round(x,3)==x for x in vals): return Precision.METER_100,[]
    if pc=='METER_10' and all(round(x,4)==x for x in vals): return Precision.METER_10,[]
    return Precision.EXACT,[f'body:{p}' for _,p in lat+lon]

def inspect_structured_payload(fields:dict, headers:dict|None=None):
    """Best-effort structured inspection. It cannot inspect encrypted/opaque/custom encodings."""
    coarse,suspicious=_coarse_coordinate_class(fields)
    # Coordinates in headers are treated as exact in this reference profile.
    hlat,hlon,hcontainers=_coordinate_values(headers or {})
    if hlat or hlon or hcontainers:
        return Precision.EXACT,[f'header:{p}' for _,p in hlat+hlon]+[f'header:{p}' for p in hcontainers]
    if coarse is not None: return coarse,suspicious
    keys=[]
    for k,v,path in _walk(fields): keys.append(k)
    s=set(keys)
    if s & METER10_KEYS: return Precision.METER_10,[]
    if s & GEOHASH_KEYS: return Precision.GEOHASH,[]
    if s & GRID_KEYS: return Precision.GRID,[]
    if s & CITY_KEYS: return Precision.CITY,[]
    if s & REGION_KEYS: return Precision.REGION,[]
    if s & COUNTRY_KEYS: return Precision.COUNTRY,[]
    return Precision.NONE,[]
