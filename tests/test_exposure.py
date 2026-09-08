from datetime import datetime,timezone
from precision_egress.state import ExposureStore
from precision_egress.models import ReleaseEvent,Precision,Risk

def test_exposure_low():
 s=ExposureStore(); snap=s.snapshot('x'); assert snap['movement_history_risk']==Risk.LOW

def test_exposure_medium():
 s=ExposureStore(); now=datetime.now(timezone.utc)
 for i in range(20): s.record(ReleaseEvent(at=now,subject_scope='x',destination_id='d',precision=Precision.CITY,fields=['city']))
 assert s.snapshot('x',now=now)['movement_history_risk']==Risk.MEDIUM

def test_exposure_high_distinct():
 s=ExposureStore(); now=datetime.now(timezone.utc)
 for i in range(8): s.record(ReleaseEvent(at=now,subject_scope='x',destination_id=f'd{i}',precision=Precision.CITY,fields=['city']))
 assert s.snapshot('x',now=now)['movement_history_risk']==Risk.HIGH

def test_exposure_critical_fine_repetition():
 s=ExposureStore(); now=datetime.now(timezone.utc)
 for i in range(100): s.record(ReleaseEvent(at=now,subject_scope='x',destination_id='d',precision=Precision.METER_100,fields=['latitude','longitude']))
 assert s.snapshot('x',now=now)['movement_history_risk']==Risk.CRITICAL
