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

def get_railway_api_key() -> str:
    """
    Railway 인증 키 조회:
    1. 환경변수 RAILWAY_API_KEY
    2. Streamlit Secrets (st.secrets["RAILWAY_API_KEY"])
    3. 팀 프로젝트 기본 키 (20110313) 자동 폴백
    """
    key = _get_env_or_secret("RAILWAY_API_KEY", "")
    if not key:
        key = DEFAULT_RAILWAY_API_KEY
    return key

RAILWAY_API_KEY = get_railway_api_key()

_cached_railway_events: List[Dict[str, Any]] = []
_railway_collection_enabled: bool = False


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
                local_ip = item.get("local_ip") or raw_info.get("local_ip") or "192.168.100.99"
                
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
            return enriched
    except Exception as e:
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

        if ev_type == "FILE_UPLOAD_ATTEMPT" or source == "chrome-extension":
            events.append(
                SecurityEvent(
                    event_id=ev_id,
                    timestamp=dt,
                    log_source=LogSource.CHROME_EXTENSION,
                    actor=Actor(user_id=user, src_ip=local_ip),
                    target=Target(domain=domain, hostname=pc),
                    action=EventAction.FILE_UPLOAD_ATTEMPT,
                    payload=PayloadMetadata(
                        file_name=file_name,
                        file_size=file_size,
                        bytes_sent=file_size,
                        category="Shadow_AI_Exfiltration" if is_ai else "File_Upload_Attempt",
                        extra={
                            "pc_name": pc,
                            "source": source,
                            "file_name": file_name,
                            "file_size": file_size,
                            "file_size_formatted": item.get("file_size_formatted", "-"),
                            "risk_score": item.get("risk_score", 0)
                        }
                    ),
                    raw_message=f"{item.get('event_time')} user={user} pc={pc} ip={local_ip} event=FILE_UPLOAD_ATTEMPT target={domain} file={file_name} size={file_size}B"
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
