import pytest
from precision_egress.models import *
from precision_egress.transform import transform_location,randomized_100m,geohash_encode
from precision_egress.inspector import inspect_structured_payload
from precision_egress.scenarios import RAW

@pytest.mark.parametrize('p,keys',[(Precision.EXACT,{'latitude','longitude','accuracy_meters'}),(Precision.METER_10,{'latitude','longitude','precision_class'}),(Precision.METER_100,{'latitude','longitude','precision_class'}),(Precision.GRID,{'grid_id'}),(Precision.GEOHASH,{'geohash'}),(Precision.CITY,{'city','region','country'}),(Precision.REGION,{'region','country'}),(Precision.COUNTRY,{'country'})])
def test_transform_shapes(p,keys): assert set(transform_location(RAW,p))==keys

def test_randomized_is_deterministic_for_reference_vector(): assert randomized_100m(RAW,'nonce-A')==randomized_100m(RAW,'nonce-A')
def test_randomized_changes_with_nonce(): assert randomized_100m(RAW,'nonce-A')!=randomized_100m(RAW,'nonce-B')
def test_geohash_length(): assert len(geohash_encode(RAW.latitude,RAW.longitude,5))==5

@pytest.mark.parametrize('fields,expected',[
 ({'latitude':1,'longitude':2},Precision.EXACT),({'accuracy_meters':10},Precision.METER_10),({'geohash':'abcde'},Precision.GEOHASH),({'grid_id':'g:1:2'},Precision.GRID),({'city':'X'},Precision.CITY),({'region':'Y'},Precision.REGION),({'country':'IN'},Precision.COUNTRY),({},Precision.NONE)])
def test_inspector(fields,expected): assert inspect_structured_payload(fields)[0]==expected

def test_nested_exact_detected(): assert inspect_structured_payload({'meta':{'latitude':1,'longitude':2}})[0]==Precision.EXACT
def test_header_exact_detected(): assert inspect_structured_payload({'city':'X'},{'latitude':1,'longitude':2})[0]==Precision.EXACT

def test_meter100_transform_inspects_as_meter100(): assert inspect_structured_payload(transform_location(RAW,Precision.METER_100))[0]==Precision.METER_100
def test_meter10_transform_inspects_as_meter10(): assert inspect_structured_payload(transform_location(RAW,Precision.METER_10))[0]==Precision.METER_10
def test_exact_coordinates_cannot_hide_behind_meter100_label(): assert inspect_structured_payload({'latitude':21.494321,'longitude':86.932145,'precision_class':'METER_100'})[0]==Precision.EXACT
