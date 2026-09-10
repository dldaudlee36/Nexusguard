"""
NexusGuard - SOAR Response Hook Module
위험 상태 전이 및 인시던트 발생 시 자동 대응/전파를 수행하는 단일 확장 훅

=====================================================================
[이 파일이 하는 일]
=====================================================================
correlation.py 가 사용자 상태를 바꿀 때마다 이 파일의 함수를 부른다.
"상태가 바뀌었으니 알려라"는 신호를 받아 알림을 보내는 곳이다.

[SOAR 란]
Security Orchestration, Automation and Response의 약자다.
보안 사고가 났을 때 사람이 일일이 손으로 하던 조치
(방화벽 막기, 계정 잠그기, 팀에 알리기)를 한곳에 모아둔 것을 말한다.

[훅(hook)이란]
"어떤 일이 일어나면 자동으로 불리는 함수"를 훅이라고 한다.
엔진은 상태를 바꾸고 나서 on_risk_state_changed()를 부르기만 하면 되고,
그 뒤에 무엇을 할지(슬랙 알림? 메일? 문자?)는 이 파일만 고치면 된다.
엔진 코드는 손댈 필요가 없다. 이렇게 나눠두면 나중에 알림 수단을 바꾸기 쉽다.

[★ 2단계 알림 구조가 구현된 곳]
  WATCH 승격 → #watch-list 채널로 1차 주의 알림
  HIGH 확정  → #incident-critical 채널로 2차 긴급 알림
채널을 나눈 이유: 1차 알림까지 긴급 채널에 넣으면
정말 급한 2차 알림이 묻혀버리기 때문이다.

[⚠ 현재 상태 — 실제로는 알림이 나가지 않는다]
아래 notify_slack()은 logger.info()로 로그만 찍고 끝난다.
실제 슬랙 웹훅 호출 코드는 아직 없다.
따라서 관리자가 대시보드를 보고 있지 않으면 WATCH 승격을 알 방법이 없다.
실제로 알림을 받으려면 notify_slack() 안에 requests.post() 를 추가해야 한다.

[⚠ 자동 차단은 일부러 꺼져 있다]
아래 on_risk_state_changed() 안의 block_outbound_ip / revoke_user_session 호출은
주석 처리되어 있다. 실수로 지운 게 아니라 의도적인 설계다.

NexusGuard는 시스템이 자동으로 차단하지 않는다.
오탐일 경우 멀쩡한 직원의 업무를 시스템이 마비시킬 수 있기 때문이다.
차단 여부는 관리자가 대시보드에서 근거를 확인하고 직접 결정한다.
"""

import logging
from typing import List, Optional
from datetime import datetime

# 'nexusguard.soar' 이름표를 단 로거.
# 나중에 이 이름으로 필터링하면 SOAR 관련 로그만 따로 볼 수 있다.
logger = logging.getLogger("nexusguard.soar")


def notify_slack(message: str, channel: str = "#incident-alerts") -> bool:
    """
    Slack 웹훅 알림 발송 (시뮬레이션 / 실제 연동 가능)

    ⚠ 지금은 실제로 슬랙에 보내지 않는다. 로그만 남긴다.
      실제 발송을 붙이려면 아래 주석 위치에 requests.post(웹훅URL, json={...}) 를 넣으면 된다.
      항상 True를 돌려주므로 호출한 쪽은 성공한 것으로 인식한다.
    """
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    log_msg = f"[SLACK WEBHOOK -> {channel}] [{timestamp}] {message}"
    logger.info(log_msg)
    # 실제 Slack Webhook URL 환경변수가 설정되어 있을 경우 requests.post() 수행 가능
    return True


def on_risk_state_changed(user: str, old_state: str, new_state: str, reasons: List[str], incident=None) -> None:
    """
    사용자 위험 상태 전이 시 자동 호출되는 범용 훅
    - NORMAL -> WATCH: 1차 사전 알림 (감시 대상 등록)
    - WATCH -> HIGH: 2차 긴급 알림 (Incident 확정)
    - WATCH -> NORMAL: 30분 만료 오탐 자동 해제 감사 로깅

    correlation.py 의 _apply_state_transition() 마지막 줄에서 호출된다.

    인자 설명:
      user      : 대상 사용자 (계정명 또는 IP)
      old_state : 바뀌기 전 상태
      new_state : 바뀐 후 상태
      reasons   : 왜 바뀌었는지 근거 목록
      incident  : HIGH일 때만 전달되는 인시던트 객체 (WATCH일 땐 None)
    """
    # 근거 목록을 한 줄 문자열로 합친다. 근거가 없으면 '단순 경과'로 표시.
    reason_str = " | ".join(reasons) if reasons else "단순 경과"

    # ── 1차 알림: 감시 대상 등록 ──────────────────────────────
    # 아직 데이터는 나가지 않았다. 관리자에게 "지켜보라"고 알리는 단계.
    if new_state == "WATCH":
        msg = f"⚠️ [1차 사전 감시] 사용자 '{user}' 감시 대상(WATCH) 승격 (사유: {reason_str})"
        notify_slack(msg, channel="#watch-list")

    # ── 2차 알림: 침해사고 확정 ───────────────────────────────
    # 실제로 데이터가 나갔다. 즉시 조치가 필요한 단계.
    elif new_state == "HIGH":
        # incident 객체가 넘어오지 않은 경우에도 알림은 나가야 하므로 기본값을 준비한다
        inc_title = incident.title if incident else "민감정보 외부 반출 의심"
        inc_id = incident.incident_id if incident else "INC-AUTO"
        msg = f"🚨 [2차 긴급 경보] [{inc_id}] '{user}' HIGH Incident 확정! (제목: {inc_title}, 근거: {reason_str})"
        notify_slack(msg, channel="#incident-critical")

        # [SOAR 확장 포인트: 필요 시 주석 해제하여 활성화]
        # ↓ 이 두 줄은 의도적으로 꺼둔 것이다. 파일 상단 설명 참고.
        #   자동 차단을 켜면 오탐 시 정상 직원의 업무가 시스템에 의해 끊긴다.
        #   현재 설계에서는 관리자가 대시보드에서 직접 실행한다.
        # if incident and hasattr(incident, 'actor'):
        #     block_outbound_ip(incident.actor)
        # revoke_user_session(user)

    # ── 자가 치유 기록 ────────────────────────────────────────
    # 30분간 아무 일도 없어서 정상으로 돌아온 경우. 긴급하지 않으므로 감사용 채널로 보낸다.
    elif old_state == "WATCH" and new_state == "NORMAL":
        msg = f"ℹ️ [오탐 자동 해제] 사용자 '{user}' 30분 TTL 만료로 정상(NORMAL) 자동 복귀 완료."
        notify_slack(msg, channel="#watch-audit")


# ============================================================================
# 실제 차단 조치 함수들
# 지금은 로그만 남기는 껍데기다. 실제 장비 연동 시 이 안을 채우면 된다.
# 대시보드의 대응 버튼이나 위 훅에서 호출하도록 연결한다.
# ============================================================================

def block_outbound_ip(target_ip: str) -> bool:
    """
    방화벽 아웃바운드 차단 룰 적용 훅

    실제 구현 시: 방화벽 API를 호출해 해당 IP의 외부 통신을 막는다.
    현재는 경고 로그만 남긴다.
    """
    logger.warning(f"방화벽 차단 정책 적용: {target_ip}")
    return True


def revoke_user_session(user_id: str) -> bool:
    """
    사용자 SSO 활성 세션 강제 종료 훅

    실제 구현 시: Active Directory 등에 요청해 로그인 세션을 만료시킨다.
    현재는 경고 로그만 남긴다.
    """
    logger.warning(f"사용자 세션 강제 종료: {user_id}")
    return True
