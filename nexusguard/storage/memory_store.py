"""
NexusGuard - Memory Store
시스템 상태 및 싱글톤 인스턴스 관리 저장소
"""

from typing import Optional, List, TYPE_CHECKING
from nexusguard.schemas.event import LogSource, SecurityEvent

if TYPE_CHECKING:
    from nexusguard.engine.correlation import CorrelationEngine
    from nexusguard.engine.governance import ShadowAIGovernanceEngine


class AppContext:
    _instance: Optional["AppContext"] = None

    def __init__(self):
        from nexusguard.engine.correlation import CorrelationEngine
        from nexusguard.engine.governance import ShadowAIGovernanceEngine
        
        self.correlation_engine = CorrelationEngine(enable_mock_incidents=False)
        self.governance_engine = ShadowAIGovernanceEngine()
        self.initial_events: List[SecurityEvent] = []
        
        # 로그가 없을 시 기본 빈 상태 유지 (가짜 더미 이벤트 주입 방지)

        # 팀원들의 실제 에이전트 및 DB 이벤트 피딩 (Railway 실시간 서버 연동)
        try:
            from nexusguard.collectors.team_collector import (
                get_team_security_events, fetch_railway_events
            )
            r_logs = fetch_railway_events(timeout=5, force=True)
            self.team_events = get_team_security_events()
            if r_logs:
                self.governance_engine.sync_railway_events(r_logs)
            for ev in self.team_events:
                if ev.log_source == LogSource.DNS:
                    self.governance_engine.process_dns_event(ev)
        except Exception as e:
            self.team_events = []

    @classmethod
    def get_instance(cls) -> "AppContext":
        if cls._instance is None:
            cls._instance = AppContext()
        return cls._instance


def get_context() -> AppContext:
    return AppContext.get_instance()
