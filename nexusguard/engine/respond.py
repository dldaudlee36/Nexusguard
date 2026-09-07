"""
NexusGuard - SOAR Response Hook Module
위험 상태 전이 및 인시던트 발생 시 자동 대응/전파를 수행하는 단일 확장 훅
"""

import logging
from typing import List, Optional
from datetime import datetime

logger = logging.getLogger("nexusguard.soar")


def notify_slack(message: str, channel: str = "#incident-alerts") -> bool:
    """Slack 웹훅 알림 발송 (시뮬레이션 / 실제 연동 가능)"""
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
    """
    reason_str = " | ".join(reasons) if reasons else "단순 경과"
    
    if new_state == "WATCH":
        msg = f"⚠️ [1차 사전 감시] 사용자 '{user}' 감시 대상(WATCH) 승격 (사유: {reason_str})"
        notify_slack(msg, channel="#watch-list")

    elif new_state == "HIGH":
        inc_title = incident.title if incident else "민감정보 외부 반출 의심"
        inc_id = incident.incident_id if incident else "INC-AUTO"
        msg = f"🚨 [2차 긴급 경보] [{inc_id}] '{user}' HIGH Incident 확정! (제목: {inc_title}, 근거: {reason_str})"
        notify_slack(msg, channel="#incident-critical")

        # [SOAR 확장 포인트: 필요 시 주석 해제하여 활성화]
        # if incident and hasattr(incident, 'actor'):
        #     block_outbound_ip(incident.actor)
        # revoke_user_session(user)

    elif old_state == "WATCH" and new_state == "NORMAL":
        msg = f"ℹ️ [오탐 자동 해제] 사용자 '{user}' 30분 TTL 만료로 정상(NORMAL) 자동 복귀 완료."
        notify_slack(msg, channel="#watch-audit")


def block_outbound_ip(target_ip: str) -> bool:
    """방화벽 아웃바운드 차단 룰 적용 훅"""
    logger.warning(f"방화벽 차단 정책 적용: {target_ip}")
    return True


def revoke_user_session(user_id: str) -> bool:
    """사용자 SSO 활성 세션 강제 종료 훅"""
    logger.warning(f"사용자 세션 강제 종료: {user_id}")
    return True
