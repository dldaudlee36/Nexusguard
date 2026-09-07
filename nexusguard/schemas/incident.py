"""
NexusGuard - Incident & Governance Schema
상관분석을 통해 생성된 침해사고(Incident) 및 섀도우 IT/AI 자산 모델
"""

from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class RiskState(str, Enum):
    NORMAL = "NORMAL"
    WATCH = "WATCH"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class UserRiskRecord(BaseModel):
    user: str = Field(description="사용자 식별자")
    state: RiskState = Field(default=RiskState.NORMAL, description="현재 위험 상태")
    score: int = Field(default=0, ge=0, le=100, description="누적 위험도 점수")
    reasons: List[str] = Field(default_factory=list, description="위험 상태 진입 근거 목록")
    entered_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime = Field(description="상태 만료 일시 UTC")


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class IncidentCategory(str, Enum):
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"              # 외부 침투 및 내부 측면이동
    SHADOW_AI_EXFILTRATION = "SHADOW_AI_EXFILTRATION"  # 섀도우 AI 데이터 유출
    RANSOMWARE_PRECURSOR = "RANSOMWARE_PRECURSOR"      # 제조/OT 랜섬웨어 선행 행위
    CREDENTIAL_STUFFING_VPN = "CREDENTIAL_STUFFING_VPN"# VPN 계정 탈취 및 토르 침투
    CLOUD_API_KEY_LEAK = "CLOUD_API_KEY_LEAK"          # 클라우드 API Key 노출 및 S3 유출
    WEBSHELL_RCE = "WEBSHELL_RCE"                      # 그룹웨어 웹쉘 및 RCE 취약점
    INSIDER_DATA_THEFT = "INSIDER_DATA_THEFT"          # 퇴사자 소스코드 클라우드 반출
    PHISHING_MACRO_RECON = "PHISHING_MACRO_RECON"      # 피싱 매크로 및 AD 정찰
    CRYPTOMINING_INTRUSION = "CRYPTOMINING_INTRUSION"  # GPU 서버 침투 및 암호화폐 채굴
    UNAUTHORIZED_PORT = "UNAUTHORIZED_PORT"            # 비인가 포트 스캔 및 탐색
    BRUTE_FORCE_BURST = "BRUTE_FORCE_BURST"            # 무차별 대입 급증


class IncidentStatus(str, Enum):
    ACTIVE = "ACTIVE"          # 진행 중
    CONTAINED = "CONTAINED"    # 격리/대응 완료
    RESOLVED = "RESOLVED"      # 종료


class NetworkHop(BaseModel):
    from_node: str = Field(description="출발지 (예: Internet, 203.0.113.10, Web Server)")
    to_node: str = Field(description="목적지 (예: Web Server, Internal Server, DB Server)")
    port: int = Field(description="통신 포트 (예: 443, 22, 3306)")
    hop_type: str = Field(default="suspicious", description="정상(normal), 의심(suspicious), 침투(attack)")


class Incident(BaseModel):
    incident_id: str = Field(description="인시던트 고유 식별자 (예: INC-001)")
    title: str = Field(description="인시던트 제목")
    category: IncidentCategory = Field(description="침해 유형")
    severity: Severity = Field(description="위험 등급")
    score: int = Field(ge=0, le=100, description="상관분석 신뢰도 점수 (0-100)")
    status: IncidentStatus = Field(default=IncidentStatus.ACTIVE, description="처리 상태")
    summary: str = Field(description="공격 및 이상행위 한줄 요약")
    actor: str = Field(description="주요 행위자 (공격자 IP 또는 내부 직원 계정)")
    target_asset: str = Field(description="피해 대상 자산 또는 타깃 서비스")
    created_at: datetime = Field(default_factory=datetime.now)
    event_ids: List[str] = Field(default_factory=list, description="연관된 보안 이벤트 ID 목록")
    evidences: List[str] = Field(default_factory=list, description="상관분석 판단 근거 목록")
    network_hops: List[NetworkHop] = Field(default_factory=list, description="재구성된 네트워크 경로")
    soar_actions: List[str] = Field(default_factory=list, description="수행 가능한 자동 대응 조치")


class SanctionStatus(str, Enum):
    APPROVED = "APPROVED"          # 정식 승인됨
    CONDITIONAL = "CONDITIONAL"    # 조건부 승인 (특정 부서)
    UNAPPROVED = "UNAPPROVED"      # 미승인 (기본)
    BLOCKED = "BLOCKED"            # 차단됨


class ShadowAIAsset(BaseModel):
    domain: str = Field(description="식별된 도메인 (예: chatgpt.com)")
    service_name: str = Field(description="서비스명 (예: ChatGPT)")
    category: str = Field(description="서비스 분류 (예: 생성형 AI, 파일 공유)")
    department_count: int = Field(description="사용 부서 수")
    user_count: int = Field(description="사용 임직원 수")
    usage_frequency: str = Field(description="사용 빈도 (매일, 주간 등)")
    risk_level: Severity = Field(description="자산 위험도 (HIGH, MEDIUM, LOW)")
    ai_diagnosis: str = Field(description="LLM 진단 소견 (데이터 학습 활용 여부 등)")
    sanction_status: SanctionStatus = Field(default=SanctionStatus.UNAPPROVED)
    recommended_alternative: Optional[str] = Field(default=None, description="사내 권장 대체 도구")
    detected_at: datetime = Field(default_factory=datetime.now)
