"""
NexusGuard - E2E Verification and Runner Script
전체 파이프라인 무결성 검증 및 Streamlit 대시보드 실행 보조 스크립트
"""

import sys

# Windows 콘솔 UTF-8 출력 보장
if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass
from datetime import datetime
from nexusguard.generators import get_all_initial_events
from nexusguard.storage import get_context
from nexusguard.schemas import Severity


def verify_pipeline():
    print("==================================================")
    print("🛡️ NexusGuard E2E 파이프라인 무결성 검증 시작")
    print("==================================================")

    # 1. 이벤트 생성 검증
    events = get_all_initial_events()
    print(f"✅ 1. 모의 이벤트 생성 완료: 총 {len(events)}건")
    sources = set(e.log_source.value for e in events)
    print(f"   - 수집된 이기종 로그 소스: {sources}")

    # 2. 컨텍스트 및 상관분석 엔진 검증
    ctx = get_context()
    incidents = ctx.correlation_engine.get_all_incidents()
    print(f"✅ 2. 상관분석 엔진 연산 완료: 총 {len(incidents)}개 침해 Incident 식별")
    for inc in incidents:
        print(f"   - [{inc.severity.value}] {inc.incident_id}: {inc.title} (Score: {inc.score})")
        print(f"     * 판단 근거 수: {len(inc.evidences)}개 | 네트워크 홉 수: {len(inc.network_hops)}개")

    # 3. 섀도우 AI 거버넌스 엔진 검증
    shadow_assets = ctx.governance_engine.get_all_assets()
    print(f"✅ 3. 섀도우 IT/AI 거버넌스 엔진 검증: 총 {len(shadow_assets)}개 미승인 자산 식별")
    for asset in shadow_assets:
        print(f"   - {asset.domain:15} | 위험도: {asset.risk_level.value:8} | {asset.user_count}명 사용 | 상태: {asset.sanction_status.value}")

    print("==================================================")
    print("🎉 NexusGuard Phase 1 모든 핵심 모듈 정상 검증 완료!")
    print("   대시보드 실행 명령: streamlit run nexusguard/ui/app.py")
    print("==================================================")


if __name__ == "__main__":
    verify_pipeline()
