"""
NexusGuard - Team Agent & Railway Pipeline Collector
팀원들이 개발한 Windows Agent(NexusGuardAgent.exe) 및 Railway 중앙 서버(Flask+PostgreSQL) 실시간 연동 모듈
"""

import os
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
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

RAILWAY_URL = _get_env_or_secret("RAILWAY_URL", "https://bountiful-nature-production-22ec.up.railway.app/events")
RAILWAY_API_KEY = _get_env_or_secret("RAILWAY_API_KEY", "")

_cached_railway_events: List[Dict[str, Any]] = []
_railway_collection_enabled: bool = False


def set_railway_collection_enabled(enabled: bool):
    """Railway 로그 수집 켜기/끄기 설정"""
    global _railway_collection_enabled
    _railway_collection_enabled = enabled


def is_railway_collection_enabled() -> bool:
    """Railway 로그 수집 활성화 여부 확인"""
    return _railway_collection_enabled


def fetch_railway_events(timeout: int = 5, force: bool = False) -> List[Dict[str, Any]]:
    """
    Railway 중앙 서버의 /events API에서 실제 Agent 수집 로그를 조회.
    수집이 OFF 상태이고 force=False이면 네트워크 요청 없이 캐시 반환.
    """
    global _cached_railway_events
    if not _railway_collection_enabled and not force:
        return _cached_railway_events

    headers = {
        "X-API-Key": RAILWAY_API_KEY
    }
    try:
        response = requests.get(RAILWAY_URL, headers=headers, timeout=timeout)
        response.raise_for_status()
        data = response.json()
        if isinstance(data, list):
            _cached_railway_events = data
            return data
    except Exception as e:
        print(f"[Railway Collector] 서버 연동 오류: {e}")
    return _cached_railway_events


def fetch_activity_log_events() -> List[Dict[str, Any]]:
    """
    팀원이 생성한 guard/logs/activity.log 파일에서 DB_SELECT 및 WEB_ACCESS 로그 파싱.
    """
    candidate_paths = [
        os.path.join("data", "activity.log"),
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
    Railway 실시간 수집 로그와 로컬 activity.log를 결합하여 SecurityEvent 목록으로 정규화.
    """
    railway_logs = fetch_railway_events()
    activity_logs = fetch_activity_log_events()
    
    events: List[SecurityEvent] = []

    # 1. Railway Agent 로그 변환
    for item in railway_logs:
        try:
            t_str = item.get("event_time")
            dt = datetime.fromisoformat(t_str) if t_str else datetime.now()
        except Exception:
            dt = datetime.now()

        user = item.get("user_name") or "User"
        pc = item.get("pc_name") or "DESKTOP-OF0CMDB"
        domain = item.get("target") or "unknown"
        ev_id = f"EVT-RLY-{item.get('id', 0)}"

        events.append(
            SecurityEvent(
                event_id=ev_id,
                timestamp=dt,
                log_source=LogSource.DNS,
                actor=Actor(user_id=user, src_ip="192.168.10.45"),
                target=Target(domain=domain, hostname=pc),
                action=EventAction.QUERY,
                payload=PayloadMetadata(
                    category="SaaS_Access",
                    extra={"pc_name": pc, "source": item.get("source", "windows-agent"), "risk_score": item.get("risk_score", 0)}
                ),
                raw_message=f"{t_str} user={user} pc={pc} event={item.get('event_type')} target={domain}"
            )
        )

    # 2. Activity.log 변환
    for act in activity_logs:
        try:
            t_str = act.get("event_time")
            dt = datetime.fromisoformat(t_str) if t_str else datetime.now()
        except Exception:
            dt = datetime.now()

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
                    raw_message=f"{t_str} user={user} action=DB_SELECT target={target_name} rows={act.get('rows', 2)}"
                )
            )
        elif ev_type == "WEB_ACCESS":
            events.append(
                SecurityEvent(
                    event_id=ev_id,
                    timestamp=dt,
                    log_source=LogSource.DNS,
                    actor=Actor(user_id=user, src_ip="192.168.10.50"),
                    target=Target(domain=target_name, hostname="company-test-pc"),
                    action=EventAction.QUERY,
                    payload=PayloadMetadata(category="Cloud_Workspace"),
                    raw_message=f"{t_str} user={user} action=WEB_ACCESS domain={target_name}"
                )
            )

    events.sort(key=lambda x: x.timestamp, reverse=True)
    return events


def get_team_sim_scenarios() -> List[Dict[str, Any]]:
    """
    팀원들이 생성한 실제 로그(activity.log 및 Railway 에이전트 수집 로그)에 기반한 시뮬레이션 시나리오.
    임의의 허구 계정 대신 실제 팀원(kim, User)과 실제 타겟(customer_vault, notion.so, chatgpt.com)을 사용.
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
            "bytes": 12800000
        },
        {
            "user": "User",
            "name": "User (DESKTOP-OF0CMDB / Railway 실시간 90+건)",
            "ip": "192.168.10.45",
            "table": "customer_db",
            "query": "SELECT id, name, email, secret_note FROM customer_vault;",
            "service": "chatgpt.com",
            "dst_domain": "api.openai.com",
            "category": "Generative_AI",
            "data_desc": "실제 PC(DESKTOP-OF0CMDB) 에이전트 수집 트래픽 및 기밀 DB 조회",
            "bytes": 24500000
        }
    ]


def load_team_guide_markdown() -> str:
    """팀원 공유 초간단 가이드 마크다운 원문 로드"""
    candidate_paths = [
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
