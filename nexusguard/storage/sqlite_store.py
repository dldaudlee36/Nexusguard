"""
NexusGuard - SQLite Persistence Storage Layer
위험 상태(user_risk), 상태 이력(risk_history), 인시던트(incidents), 도메인 캐시(domain_cache) 영속화

[이 파일이 하는 일]
분석 결과를 SQLite 파일에 저장하고 다시 읽어오는 계층이다.
메모리에만 두면 대시보드를 껐다 켤 때 다 날아가므로, 반드시 디스크에 남긴다.

[테이블 4개]
  user_risk     : 사용자별 '현재' 위험 상태 (사용자당 1행, 덮어쓰기)
  risk_history  : 상태가 바뀐 '기록' (계속 쌓임, 지우지 않음)
  incidents     : 확정된 침해사고
  domain_cache  : Gemini가 진단한 도메인 결과 (매번 LLM 호출하면 느리고 비싸므로 캐시)

[user_risk 와 risk_history 를 나눈 이유]
user_risk 는 "지금 이 사람이 WATCH인가?"에 답하고,
risk_history 는 "이 사람이 예전에 WATCH였던 적 있나?"에 답한다.

두 번째 질문이 잠복형 유출(Dormant Exfiltration) 탐지의 핵심이다.
30분 TTL이 지나 user_risk에서는 NORMAL로 돌아가도 risk_history에는 기록이 남으므로,
"30분 기다렸다가 유출하면 안 걸리지 않나?"라는 우회 시도를 잡아낼 수 있다.
→ has_user_prior_watch_history() 참고

[TTL(만료) 처리 방식 주의]
이 파일은 만료된 상태를 지우는 별도 작업을 돌리지 않는다.
대신 조회할 때마다 `expires_at > 지금시각` 조건을 붙여서 만료된 것을 걸러낸다.
따라서 만료된 WATCH는 "조회 결과에서 사라질" 뿐,
"WATCH → NORMAL로 돌아갔다"는 기록이 risk_history에 자동으로 남지는 않는다.
(자가 치유 이력을 남기려면 만료를 감지하는 주기 작업이 별도로 필요하다.)
"""

import sqlite3
import json
import os
from pathlib import Path
from datetime import datetime, timedelta   # [수정됨] timedelta 추가 (최근 24시간 조회용)
from typing import List, Optional, Dict, Any

from nexusguard.schemas.incident import (
    Incident, Severity, IncidentCategory, IncidentStatus, NetworkHop, RiskState
)

# DB 파일 위치: 프로젝트 최상위 폴더의 nexusguard.db
# (이 파일 기준 storage → nexusguard → 프로젝트 루트, 이렇게 세 단계 위로 올라간다)
DEFAULT_DB_PATH = os.path.join(str(Path(__file__).resolve().parent.parent.parent), "nexusguard.db")


class SQLiteStore:
    """SQLite 파일 하나를 열고 닫으며 읽기/쓰기를 담당하는 클래스."""

    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        self._init_db()   # 객체를 만들 때 테이블이 없으면 자동으로 만든다

    def _get_conn(self) -> sqlite3.Connection:
        """
        DB 연결을 새로 만들어 돌려준다.

        row_factory = sqlite3.Row 를 설정하면 조회 결과를
        row[0] 같은 번호가 아니라 row["user"] 처럼 컬럼명으로 꺼낼 수 있다.
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """
        테이블 4개를 만든다. CREATE TABLE IF NOT EXISTS 이므로
        이미 있으면 아무 일도 하지 않는다. 매번 실행해도 안전하다.
        """
        with self._get_conn() as conn:
            cursor = conn.cursor()

            # 1. user_risk: 현재 활성 위험 상태
            #    user가 PRIMARY KEY라서 사용자당 한 행만 존재한다(최신 상태로 덮어씀).
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
            #    한 줄씩 계속 쌓인다. 지우지 않는다.
            #    잠복형 유출 추적과 사후 감사(누가 언제 왜 WATCH가 됐나)에 쓰인다.
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
            #    같은 도메인을 다시 만났을 때 Gemini를 또 호출하지 않기 위한 저장소.
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
            #    리스트 형태 항목(event_ids, evidences 등)은 JSON 문자열로 저장한다.
            #    SQLite에는 배열 타입이 없기 때문.
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

    # ========================================================================
    # 위험 상태 기계 연동 메서드
    # ========================================================================

    def get_active_risk(self, user: str) -> Optional[Dict[str, Any]]:
        """
        만료되지 않은 사용자의 현재 상태 조회 (expires_at > UTC now)

        만료된 상태는 애초에 조회되지 않으므로, 결과가 None이면
        "이 사용자는 지금 NORMAL"로 해석하면 된다.
        """
        now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM user_risk WHERE user = ? AND expires_at > ?",
                (user, now_str)
            ).fetchone()
            if row:
                d = dict(row)
                # reasons는 JSON 문자열로 저장되어 있으므로 리스트로 되돌린다
                d["reasons"] = json.loads(d["reasons"]) if d["reasons"] else []
                return d
            return None

    def get_all_active_risks(self) -> List[Dict[str, Any]]:
        """
        현재 활성화된 모든 감시/위험 사용자 목록 (WATCH, HIGH, CRITICAL)

        state != 'NORMAL' 조건이 붙어 있으므로 평상 상태 사용자는 빠진다.
        대시보드의 '감시 대상 목록'에 쓰인다.
        """
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
        """
        모든 사용자 상태 목록 (NORMAL, WATCH, HIGH, CRITICAL 포함)

        get_all_active_risks()와 달리 NORMAL도 함께 돌려준다.
        상태별 카운터를 셀 때 쓴다.
        """
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
        """
        시뮬레이션 위험 상태, 이력 및 인시던트 완전 초기화

        시연을 다시 처음부터 돌릴 때 쓴다.
        domain_cache는 지우지 않는다 — LLM 진단 결과는 재사용해도 되기 때문.
        """
        with self._get_conn() as conn:
            conn.execute("DELETE FROM user_risk")
            conn.execute("DELETE FROM risk_history")
            conn.execute("DELETE FROM incidents")
            conn.commit()

    def upsert_risk(self, user: str, state: str, score: int, reasons: List[str], expires_at: datetime):
        """
        사용자의 현재 위험 상태를 저장한다. 없으면 새로 넣고(INSERT), 있으면 갱신한다(UPDATE).

        ON CONFLICT(user) DO UPDATE 구문이 그 '없으면 넣고 있으면 갱신'을 한 번에 처리한다.
        (이런 동작을 upsert = update + insert 라고 부른다.)

        reasons는 리스트이므로 JSON 문자열로 바꿔서 저장한다.
        ensure_ascii=False 를 줘야 한글이 \\uXXXX 로 깨지지 않고 그대로 들어간다.
        """
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
        """
        상태는 그대로 두고 만료 시각만 뒤로 미룬다.

        이미 WATCH인 사람에게 또 WATCH 조건이 걸렸을 때 사용한다.
        상태가 안 바뀌었는데 알림을 또 보내면 관제사가 피곤해지므로,
        새 알림 없이 감시 시간만 연장하는 것이다. (중복 알림 억제)
        """
        exp_str = expires_at.strftime("%Y-%m-%d %H:%M:%S")
        with self._get_conn() as conn:
            conn.execute("UPDATE user_risk SET expires_at = ? WHERE user = ?", (exp_str, user))
            conn.commit()

    def append_history(self, user: str, from_state: str, to_state: str, reason: str):
        """
        상태 전이 기록을 한 줄 남긴다. 감사(audit) 목적이므로 절대 지우지 않는다.

        남는 형태 예시:
          kim_marketing | NORMAL → WATCH | 사내 기밀 DB 조회 선행 후 미승인 AI 접속
        """
        now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        with self._get_conn() as conn:
            conn.execute(
                "INSERT INTO risk_history (user, from_state, to_state, reason, at) VALUES (?, ?, ?, ?, ?)",
                (user, from_state, to_state, reason, now_str)
            )
            conn.commit()

    def get_risk_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """최근 상태 전이 이력을 최신순으로 가져온다. 대시보드 상단 감사 트레일에 표시된다."""
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM risk_history ORDER BY at DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]

    def has_user_prior_watch_history(self, user: str, within_hours: int = 24) -> bool:
        """
        해당 사용자가 최근 within_hours(기본 24시간) 안에 WATCH 상태로 승격된 이력이 있는지 확인
        (지연 잠복형 유출 Evasion 감지용)

        ★ 잠복형 유출 탐지의 핵심 함수다.

        시나리오: 김대리가 14:05에 WATCH가 됐다가 30분 뒤 TTL 만료로 NORMAL이 됐다.
                 그리고 17:00에 갑자기 대용량 파일을 외부로 보낸다.
                 지금 상태만 보면 NORMAL이라 평범한 사용자처럼 보인다.

        이때 이 함수가 risk_history를 뒤져서 "예전에 WATCH였던 사람"임을 밝혀내고,
        엔진은 이를 단순 이상치가 아닌 '지연 잠복형 유출'로 판정해 바로 HIGH로 올린다.

        [수정됨] 예전에는 기간 제한 없이 전체 이력을 조회했다.
          그러면 반년 전에 한 번 WATCH였던 사람이 오늘 파일을 올렸다는 이유로
          '잠복형 유출'로 판정되어 HIGH가 된다. 오탐이 계속 쌓이는 구조였다.
          기획 문서상 요건이 '최근 24시간'이므로 WHERE 절에 시간 조건을 넣었다.

        within_hours: 몇 시간 전까지의 이력을 볼지. 기본 24시간.
        """
        # risk_history.at 은 "YYYY-MM-DD HH:MM:SS" 형식 문자열(UTC)로 저장되므로
        # 같은 형식으로 만든 기준 시각과 문자열 비교하면 시간 비교가 그대로 성립한다.
        since_str = (datetime.utcnow() - timedelta(hours=within_hours)).strftime("%Y-%m-%d %H:%M:%S")
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT 1 FROM risk_history WHERE user = ? AND to_state = 'WATCH' AND at >= ? LIMIT 1",
                (user, since_str)
            ).fetchone()
            return row is not None

    # ========================================================================
    # 인시던트 CRUD (저장 / 전체조회 / 단건조회)
    # ========================================================================

    def save_incident(self, inc: Incident):
        """
        인시던트를 저장한다. 같은 ID가 이미 있으면 상태와 점수만 갱신한다.

        network_hops 등 리스트/객체 항목은 SQLite에 그대로 못 넣으므로
        전부 JSON 문자열로 바꿔서 저장한다. 읽을 때 다시 객체로 복원한다.
        """
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
        """
        저장된 모든 인시던트를 최신순으로 읽어 Incident 객체 리스트로 돌려준다.

        저장할 때 JSON 문자열로 바꿨던 항목들을 여기서 원래 형태로 되돌린다.
        (문자열 → json.loads → NetworkHop 객체)
        """
        with self._get_conn() as conn:
            rows = conn.execute("SELECT * FROM incidents ORDER BY created_at DESC").fetchall()
            incidents = []
            for r in rows:
                # JSON 문자열 → 파이썬 객체 복원
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
        """
        인시던트 한 건을 ID로 찾아 돌려준다. 없으면 None.
        대시보드에서 목록의 항목을 클릭해 상세 화면을 열 때 쓴다.
        """
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

    # ========================================================================
    # 도메인 캐시 CRUD
    # Gemini 진단은 느리고 비용이 드므로, 한 번 진단한 도메인은 저장해두고 재사용한다.
    # ========================================================================

    def get_domain_cache(self, domain: str) -> Optional[Dict[str, Any]]:
        """이 도메인을 예전에 진단한 적 있으면 그 결과를 돌려준다. 없으면 None(→ 새로 LLM 호출)."""
        with self._get_conn() as conn:
            r = conn.execute("SELECT * FROM domain_cache WHERE domain = ?", (domain,)).fetchone()
            return dict(r) if r else None

    def save_domain_cache(self, domain: str, service_name: str, category: str, risk_level: str,
                          ai_diagnosis: str, sanction_status: str, alternative: str):
        """
        도메인 진단 결과를 저장한다. 이미 있으면 최신 내용으로 갱신한다.

        관리자가 승인/차단 상태를 바꿀 때도 이 함수를 통해 반영된다.
        """
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
