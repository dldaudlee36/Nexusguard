"""
NexusGuard - SQLite Persistence Storage Layer
위험 상태(user_risk), 상태 이력(risk_history), 인시던트(incidents), 도메인 캐시(domain_cache) 영속화
"""

import sqlite3
import json
import os
from pathlib import Path
from datetime import datetime
from typing import List, Optional, Dict, Any

from nexusguard.schemas.incident import (
    Incident, Severity, IncidentCategory, IncidentStatus, NetworkHop, RiskState
)

DEFAULT_DB_PATH = os.path.join(str(Path(__file__).resolve().parent.parent.parent), "nexusguard.db")


class SQLiteStore:
    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_conn() as conn:
            cursor = conn.cursor()
            # 1. user_risk: 현재 활성 위험 상태
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS user_risk (
                    user TEXT PRIMARY KEY,
                    state TEXT NOT NULL,
                    score INTEGER DEFAULT 0,
                    reasons TEXT,
                    entered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    expires_at DATETIME NOT NULL
                )
            """)
            # 2. risk_history: 상태 변경 감사 이력
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS risk_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user TEXT NOT NULL,
                    from_state TEXT NOT NULL,
                    to_state TEXT NOT NULL,
                    reason TEXT,
                    at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            # 3. domain_cache: LLM 도메인 진단 결과 영구 캐시
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS domain_cache (
                    domain TEXT PRIMARY KEY,
                    service_name TEXT,
                    category TEXT,
                    risk_level TEXT,
                    ai_diagnosis TEXT,
                    sanction_status TEXT,
                    recommended_alternative TEXT,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            # 4. incidents: 생성된 동적 인시던트
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    score INTEGER DEFAULT 0,
                    status TEXT NOT NULL,
                    summary TEXT,
                    actor TEXT,
                    target_asset TEXT,
                    created_at DATETIME,
                    event_ids TEXT,
                    evidences TEXT,
                    network_hops TEXT,
                    soar_actions TEXT
                )
            """)
            conn.commit()

    # --- 위험 상태 기계 연동 메서드 ---
    def get_active_risk(self, user: str) -> Optional[Dict[str, Any]]:
        """만료되지 않은 사용자의 현재 상태 조회 (expires_at > UTC now)"""
        now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM user_risk WHERE user = ? AND expires_at > ?",
                (user, now_str)
            ).fetchone()
            if row:
                d = dict(row)
                d["reasons"] = json.loads(d["reasons"]) if d["reasons"] else []
                return d
            return None

    def get_all_active_risks(self) -> List[Dict[str, Any]]:
        """현재 활성화된 모든 감시/위험 사용자 목록 (WATCH, HIGH, CRITICAL)"""
        now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM user_risk WHERE expires_at > ? AND state != 'NORMAL' ORDER BY entered_at DESC",
                (now_str,)
            ).fetchall()
            results = []
            for r in rows:
                d = dict(r)
                d["reasons"] = json.loads(d["reasons"]) if d["reasons"] else []
                results.append(d)
            return results

    def get_all_risks(self) -> List[Dict[str, Any]]:
        """모든 사용자 상태 목록 (NORMAL, WATCH, HIGH, CRITICAL 포함)"""
        now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM user_risk WHERE expires_at > ? ORDER BY entered_at DESC",
                (now_str,)
            ).fetchall()
            results = []
            for r in rows:
                d = dict(r)
                d["reasons"] = json.loads(d["reasons"]) if d["reasons"] else []
                results.append(d)
            return results

    def clear_all(self):
        """시뮬레이션 위험 상태, 이력 및 인시던트 완전 초기화"""
        with self._get_conn() as conn:
            conn.execute("DELETE FROM user_risk")
            conn.execute("DELETE FROM risk_history")
            conn.execute("DELETE FROM incidents")
            conn.commit()

    def upsert_risk(self, user: str, state: str, score: int, reasons: List[str], expires_at: datetime):
        now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        exp_str = expires_at.strftime("%Y-%m-%d %H:%M:%S")
        reasons_json = json.dumps(reasons, ensure_ascii=False)
        with self._get_conn() as conn:
            conn.execute("""
                INSERT INTO user_risk (user, state, score, reasons, entered_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(user) DO UPDATE SET
                    state=excluded.state, score=excluded.score, reasons=excluded.reasons,
                    entered_at=excluded.entered_at, expires_at=excluded.expires_at
            """, (user, state, score, reasons_json, now_str, exp_str))
            conn.commit()

    def extend_expiry(self, user: str, expires_at: datetime):
        exp_str = expires_at.strftime("%Y-%m-%d %H:%M:%S")
        with self._get_conn() as conn:
            conn.execute("UPDATE user_risk SET expires_at = ? WHERE user = ?", (exp_str, user))
            conn.commit()

    def append_history(self, user: str, from_state: str, to_state: str, reason: str):
        now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        with self._get_conn() as conn:
            conn.execute(
                "INSERT INTO risk_history (user, from_state, to_state, reason, at) VALUES (?, ?, ?, ?, ?)",
                (user, from_state, to_state, reason, now_str)
            )
            conn.commit()

    def get_risk_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM risk_history ORDER BY at DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]

    def has_user_prior_watch_history(self, user: str) -> bool:
        """해당 사용자가 과거에 WATCH 상태로 승격된 이력이 있는지 확인 (지연 잠복형 유출 Evasion 감지용)"""
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT 1 FROM risk_history WHERE user = ? AND to_state = 'WATCH' LIMIT 1",
                (user,)
            ).fetchone()
            return row is not None

    # --- 인시던트 CRUD ---
    def save_incident(self, inc: Incident):
        hops_json = json.dumps([h.dict() for h in inc.network_hops], ensure_ascii=False)
        evs_json = json.dumps(inc.evidences, ensure_ascii=False)
        evts_json = json.dumps(inc.event_ids, ensure_ascii=False)
        soar_json = json.dumps(inc.soar_actions, ensure_ascii=False)
        dt_str = inc.created_at.strftime("%Y-%m-%d %H:%M:%S")
        with self._get_conn() as conn:
            conn.execute("""
                INSERT INTO incidents (
                    incident_id, title, category, severity, score, status,
                    summary, actor, target_asset, created_at, event_ids, evidences, network_hops, soar_actions
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(incident_id) DO UPDATE SET
                    status=excluded.status, score=excluded.score
            """, (
                inc.incident_id, inc.title, inc.category.value, inc.severity.value, inc.score,
                inc.status.value, inc.summary, inc.actor, inc.target_asset, dt_str,
                evts_json, evs_json, hops_json, soar_json
            ))
            conn.commit()

    def get_all_incidents(self) -> List[Incident]:
        with self._get_conn() as conn:
            rows = conn.execute("SELECT * FROM incidents ORDER BY created_at DESC").fetchall()
            incidents = []
            for r in rows:
                hops = [NetworkHop(**h) for h in json.loads(r["network_hops"])] if r["network_hops"] else []
                evs = json.loads(r["evidences"]) if r["evidences"] else []
                evts = json.loads(r["event_ids"]) if r["event_ids"] else []
                soar = json.loads(r["soar_actions"]) if r["soar_actions"] else []
                incidents.append(Incident(
                    incident_id=r["incident_id"],
                    title=r["title"],
                    category=IncidentCategory(r["category"]),
                    severity=Severity(r["severity"]),
                    score=r["score"],
                    status=IncidentStatus(r["status"]),
                    summary=r["summary"],
                    actor=r["actor"],
                    target_asset=r["target_asset"],
                    created_at=datetime.strptime(r["created_at"], "%Y-%m-%d %H:%M:%S"),
                    event_ids=evts,
                    evidences=evs,
                    network_hops=hops,
                    soar_actions=soar
                ))
            return incidents

    def get_incident(self, inc_id: str) -> Optional[Incident]:
        with self._get_conn() as conn:
            r = conn.execute("SELECT * FROM incidents WHERE incident_id = ?", (inc_id,)).fetchone()
            if not r:
                return None
            hops = [NetworkHop(**h) for h in json.loads(r["network_hops"])] if r["network_hops"] else []
            evs = json.loads(r["evidences"]) if r["evidences"] else []
            evts = json.loads(r["event_ids"]) if r["event_ids"] else []
            soar = json.loads(r["soar_actions"]) if r["soar_actions"] else []
            return Incident(
                incident_id=r["incident_id"],
                title=r["title"],
                category=IncidentCategory(r["category"]),
                severity=Severity(r["severity"]),
                score=r["score"],
                status=IncidentStatus(r["status"]),
                summary=r["summary"],
                actor=r["actor"],
                target_asset=r["target_asset"],
                created_at=datetime.strptime(r["created_at"], "%Y-%m-%d %H:%M:%S"),
                event_ids=evts,
                evidences=evs,
                network_hops=hops,
                soar_actions=soar
            )

    # --- 도메인 캐시 CRUD ---
    def get_domain_cache(self, domain: str) -> Optional[Dict[str, Any]]:
        with self._get_conn() as conn:
            r = conn.execute("SELECT * FROM domain_cache WHERE domain = ?", (domain,)).fetchone()
            return dict(r) if r else None

    def save_domain_cache(self, domain: str, service_name: str, category: str, risk_level: str,
                          ai_diagnosis: str, sanction_status: str, alternative: str):
        now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        with self._get_conn() as conn:
            conn.execute("""
                INSERT INTO domain_cache (domain, service_name, category, risk_level, ai_diagnosis, sanction_status, recommended_alternative, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(domain) DO UPDATE SET
                    service_name=excluded.service_name, category=excluded.category, risk_level=excluded.risk_level,
                    ai_diagnosis=excluded.ai_diagnosis, sanction_status=excluded.sanction_status,
                    recommended_alternative=excluded.recommended_alternative, updated_at=excluded.updated_at
            """, (domain, service_name, category, risk_level, ai_diagnosis, sanction_status, alternative, now_str))
            conn.commit()
