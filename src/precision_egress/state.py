from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from threading import Lock
from collections import defaultdict
from .models import ProtectedEvidence, ReleaseEvent, Precision, PRECISION_RANK, Risk
from .canonical import digest

@dataclass
class CurrentState:
    policy_epoch:int=42
    authority_epoch:int=11
    revocation_epoch:int=7
    allowed_jurisdictions:set[str]=field(default_factory=lambda:{'IN','US','GB','DE','FR','EU'})
    authorized_sinks:set[str]=field(default_factory=lambda:{'egress-sink-01','os-broker-01','browser-sink-01','api-sink-01','telemetry-sink-01','file-sink-01'})
    user_authorized:bool=True

class EvidenceStore:
    def __init__(self): self._lock=Lock(); self._items={}; self._last=None
    def commit(self, evidence_base:dict)->ProtectedEvidence:
        with self._lock:
            base=dict(evidence_base); base['previous_evidence_digest']=self._last
            ed=digest(base)
            ev=ProtectedEvidence(**base,evidence_digest=ed)
            self._items[ev.evidence_id]=ev; self._last=ed; return ev
    def get(self,eid): return self._items.get(eid)
    def remove(self,eid): self._items.pop(eid,None)
    def __len__(self): return len(self._items)

class ActivationStore:
    """Sink-local reference state. Possession of authority alone is insufficient."""
    def __init__(self): self._lock=Lock(); self._active={}; self._used=set(); self._nonces=set()
    def activate(self, authority_id, commitment, nonce):
        with self._lock:
            if nonce in self._nonces: raise ValueError('nonce already activated')
            self._active[authority_id]=(commitment,nonce); self._nonces.add(nonce)
    def check(self, authority_id, commitment):
        with self._lock:
            return self._active.get(authority_id,(None,None))[0]==commitment and authority_id not in self._used
    def consume(self, authority_id, commitment):
        with self._lock:
            if authority_id in self._used: return False
            if self._active.get(authority_id,(None,None))[0] != commitment: return False
            self._used.add(authority_id); return True
    def is_used(self,authority_id):
        with self._lock: return authority_id in self._used
    def remove(self,authority_id):
        with self._lock: self._active.pop(authority_id,None)

class ExposureStore:
    """Illustrative local cumulative-disclosure accumulator, not a standardized policy."""
    def __init__(self): self._lock=Lock(); self._events=defaultdict(list)
    def record(self,event:ReleaseEvent):
        with self._lock: self._events[event.subject_scope].append(event)
    def snapshot(self,subject_scope,window_seconds=86400,now=None):
        now=now or datetime.now(timezone.utc); cutoff=now-timedelta(seconds=window_seconds)
        with self._lock:
            ev=[e for e in self._events.get(subject_scope,[]) if e.at>=cutoff]
        if not ev: return {'prior_release_count':0,'prior_precision_max':None,'distinct_destinations':0,'movement_history_risk':Risk.LOW}
        finest=min((e.precision for e in ev), key=lambda p: PRECISION_RANK[p])
        n=len(ev); distinct=len({e.destination_id for e in ev})
        # Illustrative reference thresholds only; not protocol requirements.
        if n>=500 or (n>=100 and PRECISION_RANK[finest] <= PRECISION_RANK[Precision.METER_100]): risk=Risk.CRITICAL
        elif n>=100 or distinct>=8: risk=Risk.HIGH
        elif n>=20 or distinct>=4: risk=Risk.MEDIUM
        else: risk=Risk.LOW
        return {'prior_release_count':n,'prior_precision_max':finest,'distinct_destinations':distinct,'movement_history_risk':risk}

class SQLiteEvidenceStore:
    """Durable reference evidence store using SQLite. Not tamper/rollback resistant."""
    def __init__(self,path):
        import sqlite3
        self.path=str(path); self._lock=Lock(); self._db=sqlite3.connect(self.path,check_same_thread=False,isolation_level=None)
        self._db.execute('PRAGMA journal_mode=WAL')
        self._db.execute('CREATE TABLE IF NOT EXISTS evidence (seq INTEGER PRIMARY KEY AUTOINCREMENT, evidence_id TEXT UNIQUE NOT NULL, body TEXT NOT NULL, digest TEXT NOT NULL)')
    def commit(self,evidence_base:dict)->ProtectedEvidence:
        import json
        with self._lock:
            row=self._db.execute('SELECT digest FROM evidence ORDER BY seq DESC LIMIT 1').fetchone(); prev=row[0] if row else None
            base=dict(evidence_base); base['previous_evidence_digest']=prev; ed=digest(base); ev=ProtectedEvidence(**base,evidence_digest=ed)
            body=ev.model_dump_json()
            self._db.execute('INSERT INTO evidence(evidence_id,body,digest) VALUES(?,?,?)',(ev.evidence_id,body,ed)); return ev
    def get(self,eid):
        row=self._db.execute('SELECT body FROM evidence WHERE evidence_id=?',(eid,)).fetchone(); return ProtectedEvidence.model_validate_json(row[0]) if row else None
    def remove(self,eid): self._db.execute('DELETE FROM evidence WHERE evidence_id=?',(eid,))

class SQLiteActivationStore:
    """Durable single-use activation state. SQLite durability is not hardware anti-rollback."""
    def __init__(self,path):
        import sqlite3
        self.path=str(path); self._lock=Lock(); self._db=sqlite3.connect(self.path,check_same_thread=False,isolation_level=None)
        self._db.execute('PRAGMA journal_mode=WAL')
        self._db.execute('CREATE TABLE IF NOT EXISTS activation (authority_id TEXT PRIMARY KEY, commitment TEXT NOT NULL, nonce TEXT UNIQUE NOT NULL, used INTEGER NOT NULL DEFAULT 0)')
    def activate(self,authority_id,commitment,nonce):
        with self._lock: self._db.execute('INSERT INTO activation(authority_id,commitment,nonce,used) VALUES(?,?,?,0)',(authority_id,commitment,nonce))
    def check(self,authority_id,commitment):
        row=self._db.execute('SELECT commitment,used FROM activation WHERE authority_id=?',(authority_id,)).fetchone(); return bool(row and row[0]==commitment and row[1]==0)
    def consume(self,authority_id,commitment):
        with self._lock:
            self._db.execute('BEGIN IMMEDIATE')
            try:
                row=self._db.execute('SELECT commitment,used FROM activation WHERE authority_id=?',(authority_id,)).fetchone()
                if not row or row[0]!=commitment or row[1]!=0: self._db.execute('ROLLBACK'); return False
                self._db.execute('UPDATE activation SET used=1 WHERE authority_id=?',(authority_id,)); self._db.execute('COMMIT'); return True
            except Exception:
                self._db.execute('ROLLBACK'); raise
    def is_used(self,authority_id):
        row=self._db.execute('SELECT used FROM activation WHERE authority_id=?',(authority_id,)).fetchone(); return bool(row and row[0])
    def remove(self,authority_id): self._db.execute('DELETE FROM activation WHERE authority_id=?',(authority_id,))
