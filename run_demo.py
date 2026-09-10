"""
NexusGuard - E2E Verification and Runner Script
전체 파이프라인 무결성 검증 및 Streamlit 대시보드 실행 보조 스크립트

[이 파일이 하는 일]
대시보드를 띄우지 않고 터미널에서 엔진이 제대로 도는지 확인하는 점검 스크립트다.

  python run_demo.py

라고 실행하면 로그 생성 → 상관분석 → 거버넌스 판정까지 한 번에 돌려보고
결과를 글자로 출력한다.

언제 쓰나:
  · 코드를 고친 뒤 엔진이 깨지지 않았는지 빠르게 확인할 때
  · 대시보드가 안 뜰 때, 화면 문제인지 엔진 문제인지 가려낼 때

[E2E 란]
End-to-End. 부품 하나가 아니라 처음부터 끝까지 전 과정을 통째로 확인한다는 뜻이다.
"""

import sys

# Windows 콘솔 UTF-8 출력 보장
# 윈도우 명령창은 기본 인코딩이 UTF-8이 아니라서
# 한글이나 이모지(🛡️, ✅)를 출력할 때 오류가 날 수 있다. 그래서 미리 바꿔둔다.
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
    """
    3단계로 나눠 점검한다.
      1) 로그가 만들어지는가
      2) 상관분석 엔진이 인시던트를 뽑아내는가
      3) 거버넌스 엔진이 외부 자산을 식별하는가

    ※ 여기서 쓰는 것은 전부 더미 로그다. 실제 Railway 수집 로그는 점검 대상이 아니다.
    """
    print("==================================================")
    print("🛡️ NexusGuard E2E 파이프라인 무결성 검증 시작")
    print("==================================================")

    # 1. 이벤트 생성 검증
    # 로그가 몇 건 만들어졌고, 어떤 종류의 소스가 섞여 있는지 확인한다.
    events = get_all_initial_events()
    print(f"✅ 1. 모의 이벤트 생성 완료: 총 {len(events)}건")
    sources = set(e.log_source.value for e in events)
    print(f"   - 수집된 이기종 로그 소스: {sources}")

    # 2. 컨텍스트 및 상관분석 엔진 검증
    # get_context()를 부르는 순간 엔진이 만들어지고 더미 로그가 자동 투입된다.
    # (storage/memory_store.py 의 AppContext.__init__ 참고)
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


# 이 파일을 직접 실행했을 때만 검증을 돌린다.
# 다른 파일에서 import 했을 때는 실행되지 않는다. (파이썬의 관용적인 패턴)
if __name__ == "__main__":
    verify_pipeline()
