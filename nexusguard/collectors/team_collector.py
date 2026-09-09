"""
NexusGuard - Team Agent & Railway Pipeline Collector
팀원들이 개발한 Windows Agent(NexusGuardAgent.exe) 및 Railway 중앙 서버(Flask+PostgreSQL) 실시간 연동 모듈
"""

import os
import ast
import json
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from email.utils import parsedate_to_datetime
import requests

try:
    from dotenv import load_dotenv
    root_env = Path(__file__).resolve().parent.parent.parent / ".env"
    if root_env.exists():
        load_dotenv(root_env)
    else:
        load_dotenv()
except Exception:
    pass

def _get_env_or_secret(key: str, default: str = "") -> str:
    val = os.getenv(key, "")
    if val:
        return val
    try:
        import streamlit as st
        if hasattr(st, "secrets") and key in st.secrets:
            return str(st.secrets[key])
    except Exception:
        pass
    return default

from nexusguard.schemas.event import (
    SecurityEvent, LogSource, EventAction, Actor, Target, PayloadMetadata
)

DEFAULT_RAILWAY_API_KEY = "20110313"
RAILWAY_URL = _get_env_or_secret("RAILWAY_URL", "https://bountiful-nature-production-22ec.up.railway.app/events")

# ---------------------------------------------------------------------------
# P1: DB 유저 ↔ Windows 에이전트 계정 매핑 테이블
# MySQL general_log의 user_host(예: test_user) → Windows Agent 계정(예: User)
# 동일 인물로 식별하여 상관분석 킬체인을 연결한다.
# ---------------------------------------------------------------------------
USER_HOST_MAPPING: dict = {
    "test_user":    "User",        # MySQL Workbench 테스트 계정 → 에이전트 계정
    "root":         "User",        # root 계정도 동일 단말로 매핑
    "kim":          "kim",         # activity.log 실 계정 (변경 없음)
    "nexusguard":   "User",        # 프로젝트 전용 계정
}
# 역방향: Windows Agent 계정 → src_ip (에이전트가 수집한 로컬 IP)
AGENT_IP_MAPPING: dict = {
    "User": "192.168.100.99",      # DESKTOP-OF0CMDB 단말 IP
    "kim":  "192.168.10.50",       # activity.log 단말 IP
}

# P0: DB 감사 CSV 후보 경로 (가이드에 따라 data/ 폴더에 저장)
DB_AUDIT_CSV_PATHS = [
    os.path.join("data", "mysql_audit_log.csv"),
    os.path.join("data", "db_audit_log.csv"),
    os.path.join("data", "general_log.csv"),
    os.path.join(os.path.dirname(__file__), "..", "..", "data", "mysql_audit_log.csv"),
    os.path.join(os.path.dirname(__file__), "..", "..", "data", "db_audit_log.csv"),
]

def get_railway_api_key() -> str:
    """
    Railway 인증 키 조회:
    1. 환경변수 RAILWAY_API_KEY (.env)
    2. Streamlit Secrets (st.secrets["RAILWAY_API_KEY"])
    """
    key = _get_env_or_secret("RAILWAY_API_KEY", "")
    if not key:
        key = DEFAULT_RAILWAY_API_KEY
    return key

RAILWAY_API_KEY = get_railway_api_key()

_cached_railway_events: List[Dict[str, Any]] = []
_railway_collection_enabled: bool = True
_railway_fetch_status = {"ok": None, "last_success": None, "error": None}


def get_railway_fetch_status() -> Dict[str, Any]:
    return dict(_railway_fetch_status)


def set_railway_collection_enabled(enabled: bool):
    """Railway 로그 수집 켜기/끄기 설정"""
    global _railway_collection_enabled
    _railway_collection_enabled = enabled


def is_railway_collection_enabled() -> bool:
    """Railway 로그 수집 활성화 여부 확인"""
    return _railway_collection_enabled


def _parse_event_time(t_str: Optional[str]) -> datetime:
    """ISO 및 RFC 2822(HTTP 날짜 헤더 형식) 문자열을 datetime 객체로 파싱"""
    if not t_str:
        return datetime.utcnow()
    try:
        return datetime.fromisoformat(t_str)
    except Exception:
        pass
    try:
        dt = parsedate_to_datetime(t_str)
        if dt.tzinfo:
            return dt.replace(tzinfo=None)
        return dt
    except Exception:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%a, %d %b %Y %H:%M:%S %Z", "%a, %d %b %Y %H:%M:%S"):
        try:
            return datetime.strptime(t_str, fmt)
        except Exception:
            continue
    return datetime.utcnow()


def _parse_raw_data(raw: Any) -> Dict[str, Any]:
    """Railway DB에 문자열로 저장된 raw_data(JSON 또는 Python dict) 파싱"""
    if isinstance(raw, dict):
        return raw
    if not raw or not isinstance(raw, str):
        return {}
    raw_str = raw.strip()
    if not raw_str:
        return {}
    try:
        return json.loads(raw_str)
    except Exception:
        pass
    try:
        parsed = ast.literal_eval(raw_str)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass
    return {}


def _format_file_size(size_bytes: Optional[int]) -> str:
    """바이트 단위 파일 크기를 읽기 쉬운 문자열(KB, MB 등)로 포맷"""
    if size_bytes is None:
        return "-"
    try:
        size = float(size_bytes)
        if size < 0:
            return "-"
        if size == 0:
            return "0 B"
        for unit in ["B", "KB", "MB", "GB"]:
            if size < 1024.0:
                return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
            size /= 1024.0
        return f"{size:.1f} TB"
    except Exception:
        return str(size_bytes)


def fetch_railway_events(timeout: int = 5, force: bool = False) -> List[Dict[str, Any]]:
    """
    Railway 중앙 서버의 /events API에서 실제 Agent 수집 로그를 조회.
    수집이 OFF 상태이고 force=False이면 네트워크 요청 없이 캐시 반환.
    수집된 로그의 raw_data에서 file_name, file_size, local_ip를 자동 추출하여 정규화.
    """
    global _cached_railway_events
    if not _railway_collection_enabled and not force:
        return _cached_railway_events

    api_key = get_railway_api_key()
    headers = {
        "X-API-Key": api_key
    }
    try:
        response = requests.get(RAILWAY_URL, headers=headers, timeout=timeout)
        response.raise_for_status()
        data = response.json()
        if isinstance(data, list):
            enriched = []
            for item in data:
                raw_info = _parse_raw_data(item.get("raw_data"))
                
                # 1. 파일 업로드 관련 메타데이터 추출 (Chrome Extension 연동)
                file_name = item.get("file_name") or raw_info.get("file_name") or None
                file_size = item.get("file_size") or raw_info.get("file_size") or None
                if file_size is not None:
                    try:
                        file_size = int(file_size)
                    except (ValueError, TypeError):
                        pass
                
                # 2. 로컬 IP 추출
                local_ip = item.get("local_ip")
                if not local_ip or str(local_ip).strip().lower() in ("unknown", "none", "null", "-"):
                    local_ip = raw_info.get("local_ip") or "unknown"
                
                # 3. 이벤트 타입 정규화
                ev_type = item.get("event_type") or raw_info.get("event_type") or "WEB_ACCESS"
                
                # 4. 소스 정규화 (windows-agent / chrome-extension)
                source = item.get("source") or raw_info.get("source")
                if not source:
                    source = "chrome-extension" if ev_type == "FILE_UPLOAD_ATTEMPT" else "windows-agent"
                
                item["file_name"] = file_name
                item["file_size"] = file_size
                item["file_size_formatted"] = _format_file_size(file_size) if file_size is not None else "-"
                item["local_ip"] = local_ip
                item["event_type"] = ev_type
                item["source"] = source
                enriched.append(item)

            _cached_railway_events = enriched
            _railway_fetch_status.update(ok=True, last_success=datetime.utcnow().isoformat() + "Z", error=None)
            return enriched
        raise ValueError("서버 응답이 로그 목록 형식이 아닙니다.")
    except Exception as e:
        _railway_fetch_status.update(ok=False, error=type(e).__name__)
        print(f"[Railway Collector] 서버 연동 오류: {e}")
    return _cached_railway_events


def fetch_activity_log_events() -> List[Dict[str, Any]]:
    """
    팀원이 생성한 guard/logs/activity.log 파일에서 DB_SELECT 및 WEB_ACCESS 로그 파싱.
    """
    candidate_paths = [
        os.path.join("data", "activity.log"),
        r"C:\Users\User\Downloads\NexusguardAgent\guard\logs\activity.log",
        r"C:\Users\User\Documents\카카오톡 받은 파일\guard\logs\activity.log",
        os.path.join(os.path.dirname(__file__), "..", "..", "data", "activity.log")
    ]
    
    records = []
    log_file = None
    for p in candidate_paths:
        if os.path.exists(p):
            log_file = p
            break
            
    if not log_file:
        return records

    try:
        with open(log_file, "r", encoding="utf-8") as f:
            for idx, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue
                # 예: 2026-09-07T00:27:42.713941 user=kim action=DB_SELECT target=customer_vault rows=2
                # 예: 2026-09-07T00:12:37.839533 user=kim action=WEB_ACCESS domain=notion.so
                parts = line.split(" ")
                time_str = parts[0]
                kv = {}
                for p in parts[1:]:
                    if "=" in p:
                        k, v = p.split("=", 1)
                        kv[k] = v
                
                records.append({
                    "id": f"ACT-{idx+1}",
                    "event_time": time_str,
                    "user_name": kv.get("user", "kim"),
                    "pc_name": "company-test-pc",
                    "event_type": kv.get("action", "UNKNOWN"),
                    "source": "activity.log",
                    "target": kv.get("target") or kv.get("domain", "unknown"),
                    "rows": int(kv.get("rows", 0)) if "rows" in kv else None,
                    "risk_score": 0
                })
    except Exception as e:
        print(f"[Activity Log Collector] 파일 읽기 오류: {e}")
        
    return records


# ---------------------------------------------------------------------------
# P0: MySQL general_log CSV → SecurityEvent 주입 파서
# 가이드(NexusGuard_DB_Test_Guide.md) 기준 컬럼:
#   event_time, user_name, src_ip, action, target_table, query_string, rows_affected
# ---------------------------------------------------------------------------
def load_db_audit_csv() -> List[Dict[str, Any]]:
    """
    data/mysql_audit_log.csv 파일을 읽어 DB_SELECT 이벤트 딕셔너리 목록으로 반환.
    USER_HOST_MAPPING을 통해 DB 유저 → 에이전트 계정명으로 자동 정규화.
    파일이 없으면 빈 리스트 반환 (silent fail).
    """
    import csv

    csv_file = None
    for p in DB_AUDIT_CSV_PATHS:
        if os.path.exists(p):
            csv_file = p
            break

    if not csv_file:
        return []

    records = []
    try:
        with open(csv_file, "r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for idx, row in enumerate(reader):
                # 필수 필드 추출 (컬럼명 공백 제거)
                row = {k.strip(): v.strip() for k, v in row.items()}

                raw_user = row.get("user_name") or row.get("user") or "test_user"
                # P1: DB 유저 → Windows Agent 계정명 매핑
                mapped_user = USER_HOST_MAPPING.get(raw_user, raw_user)
                src_ip = row.get("src_ip") or AGENT_IP_MAPPING.get(mapped_user, "192.168.10.50")

                action = (row.get("action") or row.get("event_type") or "DB_SELECT").upper()
                # action이 Query(MySQL 원시값)이면 DB_SELECT로 정규화
                if action in ("QUERY", "EXECUTE"):
                    action = "DB_SELECT"

                target_table = row.get("target_table") or row.get("table_name") or "unknown_table"
                query_str = row.get("query_string") or row.get("argument") or f"SELECT * FROM {target_table};"

                rows_affected = 0
                try:
                    rows_affected = int(row.get("rows_affected") or row.get("rows") or 0)
                except (ValueError, TypeError):
                    rows_affected = 0

                event_time = row.get("event_time") or row.get("timestamp") or ""

                records.append({
                    "id": f"DB-CSV-{idx + 1}",
                    "event_time": event_time,
                    "user_name": mapped_user,           # 매핑된 계정명 (상관분석에서 사용)
                    "raw_db_user": raw_user,             # 원래 DB 유저명 (감사 로그용)
                    "src_ip": src_ip,
                    "pc_name": "db-server-01",
                    "event_type": action,
                    "source": "mysql-general-log",
                    "target": target_table,
                    "query_string": query_str,
                    "rows": rows_affected,
                    "risk_score": 0
                })

        print(f"[DB CSV Collector] {csv_file} 로드 완료: {len(records)}건")
    except Exception as e:
        print(f"[DB CSV Collector] CSV 파싱 오류: {e}")

    return records




def get_team_security_events() -> List[SecurityEvent]:
    """
    Railway 실시간 수집 로그(WEB_ACCESS 및 FILE_UPLOAD_ATTEMPT)와 로컬 activity.log를 결합하여 SecurityEvent 목록으로 정규화.
    """
    railway_logs = fetch_railway_events()
    activity_logs = fetch_activity_log_events()
    
    events: List[SecurityEvent] = []

    # 1. Railway Agent & Chrome Extension 로그 변환
    for item in railway_logs:
        dt = _parse_event_time(item.get("event_time"))
        user = item.get("user_name") or "User"
        pc = item.get("pc_name") or "DESKTOP-OF0CMDB"
        local_ip = item.get("local_ip") or "192.168.100.99"
        domain = item.get("target") or "unknown"
        ev_id = f"EVT-RLY-{item.get('id', 0)}"
        ev_type = item.get("event_type", "WEB_ACCESS")
        source = item.get("source", "windows-agent")
        file_name = item.get("file_name")
        file_size = item.get("file_size")

        is_ai = any(k in domain.lower() for k in ["chatgpt", "openai", "claude", "gemini", "copilot", "perplexity", "ai"])

        if ev_type in ("FILE_UPLOAD_ATTEMPT", "PASTE_ATTEMPT") or source == "chrome-extension":
            action = EventAction.PASTE_ATTEMPT if ev_type == "PASTE_ATTEMPT" else EventAction.FILE_UPLOAD_ATTEMPT
            events.append(
                SecurityEvent(
                    event_id=ev_id,
                    timestamp=dt,
                    log_source=LogSource.CHROME_EXTENSION,
                    actor=Actor(user_id=user, src_ip=local_ip),
                    target=Target(domain=domain, hostname=pc),
                    action=action,
                    payload=PayloadMetadata(
                        file_name=file_name,
                        file_size=file_size,
                        bytes_sent=file_size,
                        category="Shadow_AI_Exfiltration" if is_ai else ("Paste_Attempt" if ev_type == "PASTE_ATTEMPT" else "File_Upload_Attempt"),
                        extra={
                            "pc_name": pc,
                            "source": source,
                            "file_name": file_name,
                            "file_size": file_size,
                            "file_size_formatted": item.get("file_size_formatted", "-"),
                            "risk_score": item.get("risk_score", 0)
                        }
                    ),
                    raw_message=f"{item.get('event_time')} user={user} pc={pc} ip={local_ip} event={ev_type} target={domain} file={file_name} size={file_size}B"
                )
            )
        else:
            # WEB_ACCESS
            events.append(
                SecurityEvent(
                    event_id=ev_id,
                    timestamp=dt,
                    log_source=LogSource.WINDOWS_AGENT,
                    actor=Actor(user_id=user, src_ip=local_ip),
                    target=Target(domain=domain, hostname=pc),
                    action=EventAction.WEB_ACCESS,
                    payload=PayloadMetadata(
                        category="Generative_AI" if is_ai else "SaaS_Access",
                        extra={
                            "pc_name": pc,
                            "source": source,
                            "risk_score": item.get("risk_score", 0)
                        }
                    ),
                    raw_message=f"{item.get('event_time')} user={user} pc={pc} ip={local_ip} event=WEB_ACCESS target={domain}"
                )
            )

    # 2. Activity.log 변환
    for act in activity_logs:
        dt = _parse_event_time(act.get("event_time"))
        user = act.get("user_name", "kim")
        target_name = act.get("target", "customer_vault")
        ev_type = act.get("event_type", "DB_SELECT")
        ev_id = f"EVT-{act.get('id')}"

        if ev_type == "DB_SELECT":
            events.append(
                SecurityEvent(
                    event_id=ev_id,
                    timestamp=dt,
                    log_source=LogSource.DB,
                    actor=Actor(user_id=user, src_ip="192.168.10.50"),
                    target=Target(dst_ip="10.0.0.30", dst_port=3306, hostname="db-cust-01"),
                    action=EventAction.SELECT,
                    payload=PayloadMetadata(
                        query_string=f"SELECT * FROM {target_name};",
                        table_name=target_name,
                        rows_affected=act.get("rows", 2),
                        category="PrivilegedDataAccess"
                    ),
                    raw_message=f"{act.get('event_time')} user={user} action=DB_SELECT target={target_name} rows={act.get('rows', 2)}"
                )
            )
        elif ev_type == "WEB_ACCESS":
            events.append(
                SecurityEvent(
                    event_id=ev_id,
                    timestamp=dt,
                    log_source=LogSource.WINDOWS_AGENT,
                    actor=Actor(user_id=user, src_ip="192.168.10.50"),
                    target=Target(domain=target_name, hostname="company-test-pc"),
                    action=EventAction.WEB_ACCESS,
                    payload=PayloadMetadata(category="Cloud_Workspace"),
                    raw_message=f"{act.get('event_time')} user={user} action=WEB_ACCESS domain={target_name}"
                )
            )

    # 3. MySQL General Log CSV 변환 (P0: DB 감사 로그 수집 파이프라인)
    db_csv_logs = load_db_audit_csv()
    for db_row in db_csv_logs:
        dt = _parse_event_time(db_row.get("event_time"))
        user = db_row.get("user_name", "test_user")
        src_ip = db_row.get("src_ip", "192.168.10.50")
        target_table = db_row.get("target", "unknown_table")
        query_str = db_row.get("query_string", f"SELECT * FROM {target_table};")
        rows_aff = db_row.get("rows", 0)
        ev_id = f"EVT-{db_row.get('id', 'DB-0')}"
        raw_db_user = db_row.get("raw_db_user", user)

        # DB_SELECT 이벤트만 상관분석 엔진에 주입 (INSERT/UPDATE 등은 향후 확장)
        if db_row.get("event_type", "DB_SELECT") == "DB_SELECT":
            events.append(
                SecurityEvent(
                    event_id=ev_id,
                    timestamp=dt,
                    log_source=LogSource.DB,
                    actor=Actor(user_id=user, src_ip=src_ip),
                    target=Target(dst_ip="10.0.0.30", dst_port=3306, hostname="db-server-01"),
                    action=EventAction.SELECT,
                    payload=PayloadMetadata(
                        query_string=query_str,
                        table_name=target_table,
                        rows_affected=rows_aff,
                        category="PrivilegedDataAccess",
                        extra={
                            "raw_db_user": raw_db_user,
                            "source": "mysql-general-log",
                            "risk_score": db_row.get("risk_score", 0)
                        }
                    ),
                    raw_message=(
                        f"{db_row.get('event_time')} db_user={raw_db_user}"
                        f" mapped_user={user} ip={src_ip}"
                        f" action=DB_SELECT table={target_table} rows={rows_aff}"
                    )
                )
            )

    events.sort(key=lambda x: x.timestamp, reverse=True)
    return events



def get_team_sim_scenarios() -> List[Dict[str, Any]]:
    """
    팀원들이 생성한 실제 로그(activity.log 및 Railway 에이전트/Chrome 확장 수집 로그)에 기반한 시뮬레이션 시나리오.
    """
    return [
        {
            "user": "kim",
            "name": "kim (김보안 연구원 / guard/app activity.log)",
            "ip": "192.168.10.50",
            "table": "customer_vault",
            "query": "SELECT * FROM customer_vault; (실제 활동 로그 연동, rows=2)",
            "service": "notion.so",
            "dst_domain": "file-upload.notion.so",
            "category": "Cloud_Workspace",
            "data_desc": "customer_vault 고객 개인정보 및 계좌 기밀 원장 (2건)",
            "bytes": 12800000,
            "file_name": "customer_vault_export_2026.csv",
            "file_size": 12800000
        },
        {
            "user": "User",
            "name": "User (DESKTOP-OF0CMDB / Chrome 확장 프로그램 실시간 수집 연동)",
            "ip": "192.168.100.99",
            "table": "customer_db",
            "query": "SELECT id, name, email, secret_note FROM customer_vault;",
            "service": "chatgpt.com",
            "dst_domain": "chatgpt.com",
            "category": "Generative_AI",
            "data_desc": "실제 PC(DESKTOP-OF0CMDB) 에이전트 수집 트래픽 및 Chrome 확장 파일 첨부",
            "bytes": 24500000,
            "file_name": "2026_고객_신용카드_원장_덤프.zip",
            "file_size": 24500000
        }
    ]


def load_team_guide_markdown() -> str:
    """팀원 공유 초간단 가이드 마크다운 원문 로드 (v3 우선)"""
    candidate_paths = [
        os.path.join("data", "NexusGuard_팀원공유_초간단_수집가이드_v3.md"),
        r"C:\Users\User\Downloads\NexusguardAgent\NexusGuard_팀원공유_초간단_수집가이드_v3.md",
        os.path.join("data", "NexusGuard_팀원공유_초간단가이드.md"),
        r"C:\Users\User\Documents\카카오톡 받은 파일\NexusGuard_팀원공유_초간단가이드 (2).md",
    ]
    for p in candidate_paths:
        if os.path.exists(p):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    return f.read()
            except Exception:
                pass
    return "# NexusGuard 팀원 가이드 파일을 찾을 수 없습니다."
