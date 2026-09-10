"""프롬프트 6 검증: PASTE_ATTEMPT 판정 규칙
 (a) NORMAL 사용자 -> 상태 안 바뀜 (기록만)
 (b) WATCH  사용자 -> HIGH 로 바뀜
"""
import os
import sys
from datetime import datetime, timedelta

# 이 파일이 놓인 폴더(프로젝트 루트)를 모듈 경로에 추가
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nexusguard.engine.correlation import CorrelationEngine
from nexusguard.schemas.event import (
    SecurityEvent, LogSource, EventAction, Actor, Target, PayloadMetadata
)

engine = CorrelationEngine(enable_mock_incidents=False)
engine.store.clear_all()

PATTERN_HITS = {"rrn": 3, "card": 1, "email": 12, "phone": 5}


def make_paste_event(user, eid):
    return SecurityEvent(
        event_id=eid,
        timestamp=datetime.utcnow(),
        log_source=LogSource.CHROME_EXTENSION,
        actor=Actor(user_id=user, src_ip="192.168.10.88"),
        target=Target(domain="chatgpt.com", hostname="TEST-PC"),
        action=EventAction.PASTE_ATTEMPT,
        payload=PayloadMetadata(
            category="Shadow_AI_Paste",
            extra={"text_length": 3420, "pattern_hits": PATTERN_HITS},
        ),
        raw_message="event=PASTE_ATTEMPT target=chatgpt.com text_length=3420",
    )


def state_of(user):
    r = engine.store.get_active_risk(user)
    return r["state"] if r else "NORMAL"


ok = True

# ---------- (a) NORMAL 사용자 ----------
U_NORMAL = "paste_normal_user"
print("== (a) NORMAL 사용자에게 PASTE_ATTEMPT 투입 ==")
before = state_of(U_NORMAL)
engine.ingest_events([make_paste_event(U_NORMAL, "EVT-PASTE-N1")])
after = state_of(U_NORMAL)
print(f"   상태: {before} -> {after}")
if after != "NORMAL":
    print(f"   FAIL: NORMAL 사용자의 상태가 {after} 로 바뀜")
    ok = False
else:
    print("   OK: 상태 변화 없음")

rec = [h for h in engine.store.get_risk_history(limit=200) if h["user"] == U_NORMAL]
print(f"   기록 건수: {len(rec)}")
if len(rec) != 1:
    print("   FAIL: 기록이 남지 않음")
    ok = False
else:
    print(f"   기록 내용: {rec[0]['from_state']} -> {rec[0]['to_state']}")
    print(f"   {rec[0]['reason'][:160]}...")

# ---------- (b) WATCH 사용자 ----------
U_WATCH = "paste_watch_user"
print("\n== (b) WATCH 사용자에게 PASTE_ATTEMPT 투입 ==")
engine.store.upsert_risk(
    U_WATCH, "WATCH", 68, ["테스트용 사전 감시 상태"],
    datetime.utcnow() + timedelta(minutes=30),
)
before = state_of(U_WATCH)
engine.ingest_events([make_paste_event(U_WATCH, "EVT-PASTE-W1")])
after = state_of(U_WATCH)
print(f"   상태: {before} -> {after}")
if before != "WATCH":
    print("   FAIL: 사전 조건(WATCH) 설정 실패")
    ok = False
if after != "HIGH":
    print(f"   FAIL: WATCH 사용자가 HIGH 로 승격되지 않음 (현재 {after})")
    ok = False
else:
    print("   OK: HIGH 로 승격됨")
    r = engine.store.get_active_risk(U_WATCH)
    print("   근거:")
    for line in r["reasons"]:
        print(f"     - {line}")

# ---------- 내용 미저장 확인 ----------
print("\n== 붙여넣은 내용 미저장 확인 ==")
all_text = " ".join(
    h["reason"] or "" for h in engine.store.get_risk_history(limit=500)
) + " ".join(
    str(r["reasons"]) for r in engine.store.get_all_risks()
)
if "text" in all_text.lower() and "text_length" not in all_text:
    print("   FAIL: 원문으로 보이는 값이 저장됨")
    ok = False
else:
    print("   OK: 길이와 패턴 개수만 저장됨")

engine.store.clear_all()
print("\nRESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
