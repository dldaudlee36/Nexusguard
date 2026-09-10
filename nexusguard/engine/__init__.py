# engine 패키지
# NexusGuard의 판정 두뇌.
#   CorrelationEngine        - 사용자 위험 상태 판정 (NORMAL / WATCH / HIGH)
#   ShadowAIGovernanceEngine - 외부 AI 서비스 자산 관리 및 위험도 산출
#
# __all__ 은 'from nexusguard.engine import *' 를 했을 때
# 무엇을 꺼내줄지 지정하는 목록이다.

from .correlation import CorrelationEngine
from .governance import ShadowAIGovernanceEngine

__all__ = ["CorrelationEngine", "ShadowAIGovernanceEngine"]
