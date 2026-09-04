"""
NexusGuard - Memory Store
시스템 상태 및 싱글톤 인스턴스 관리 저장소
"""

from typing import Optional
from nexusguard.engine.correlation import CorrelationEngine
from nexusguard.engine.governance import ShadowAIGovernanceEngine
from nexusguard.generators.dummy_logs import get_all_initial_events


class AppContext:
    _instance: Optional["AppContext"] = None

    def __init__(self):
        self.correlation_engine = CorrelationEngine()
        self.governance_engine = ShadowAIGovernanceEngine()
        self.initial_events = get_all_initial_events()
        
        # 초기 이벤트를 각 엔진에 피딩
        self.correlation_engine.ingest_events(self.initial_events)
        for ev in self.initial_events:
            self.governance_engine.process_dns_event(ev)

    @classmethod
    def get_instance(cls) -> "AppContext":
        if cls._instance is None:
            cls._instance = AppContext()
        return cls._instance


def get_context() -> AppContext:
    return AppContext.get_instance()
