# schemas 패키지
# 프로그램 전체가 공유하는 데이터 모양(형식) 정의.
#   event.py    - 들어오는 로그의 형식 (SecurityEvent)
#   incident.py - 분석 결과의 형식 (Incident, RiskState, ShadowAIAsset)

from .event import SecurityEvent, LogSource, EventAction, Actor, Target, PayloadMetadata
from .incident import (
    Incident, Severity, IncidentCategory, IncidentStatus, NetworkHop, ShadowAIAsset, SanctionStatus,
    RiskState, UserRiskRecord
)

__all__ = [
    "SecurityEvent",
    "LogSource",
    "EventAction",
    "Actor",
    "Target",
    "PayloadMetadata",
    "Incident",
    "Severity",
    "IncidentCategory",
    "IncidentStatus",
    "NetworkHop",
    "ShadowAIAsset",
    "SanctionStatus",
    "RiskState",
    "UserRiskRecord",
]
