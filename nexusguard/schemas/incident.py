"""
NexusGuard - Incident & Governance Schema
상관분석을 통해 생성된 침해사고(Incident) 및 섀도우 IT/AI 자산 모델

[이 파일이 하는 일]
event.py 가 '들어오는 로그'의 형태를 정의한다면,
이 파일은 '분석 결과'의 형태를 정의한다.

  - RiskState / UserRiskRecord : 사용자 한 명의 현재 위험 상태 (NORMAL / WATCH / HIGH)
  - Incident                   : 확정된 침해사고 한 건
  - ShadowAIAsset              : 사내에서 발견된 외부 AI 서비스 자산

[위험 상태 흐름 요약]
  NORMAL ──(기밀DB 조회 + 미승인 AI 접속)──▶ WATCH ──(외부 전송 발생)──▶ HIGH
     ▲                                        │
     └────────(30분간 전송 없음, TTL 만료)──────┘
"""

from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class RiskState(str, Enum):
    """
    사용자의 위험 상태. NexusGuard 설계의 핵심 개념이다.

    NORMAL   : 평상시. 아무 문제 없음
    WATCH    : 선제 감시. 유출 '준비' 정황은 보이지만 아직 데이터는 안 나갔다.
               ★ 이 단계가 NexusGuard의 차별점. 기존 보안 장비는 여기서 아무것도 안 한다.
    HIGH     : 실제로 데이터가 나갔다. 침해사고 확정
    CRITICAL : HIGH보다 심각한 경우 (대규모 유출 등)
    """
    NORMAL = "NORMAL"
    WATCH = "WATCH"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class UserRiskRecord(BaseModel):
    """
    사용자 한 명의 현재 위험 상태 기록. SQLite의 user_risk 테이블과 짝을 이룬다.

    expires_at(만료 시각)이 중요하다.
    WATCH는 30분 뒤 만료되며, 만료되면 자동으로 NORMAL로 돌아간다(자가 치유).
    만료 시각이 없으면 한 번 WATCH가 된 사람이 영원히 감시 대상으로 남아
    관제사가 지치게 되므로(Alert Fatigue), 모든 상태에는 반드시 TTL을 건다.
    """
    user: str = Field(description="사용자 식별자")
    state: RiskState = Field(default=RiskState.NORMAL, description="현재 위험 상태")
    score: int = Field(default=0, ge=0, le=100, description="누적 위험도 점수")
    reasons: List[str] = Field(default_factory=list, description="위험 상태 진입 근거 목록")
    entered_at: datetime = Field(default_factory=datetime.utcnow)  # 이 상태에 들어온 시각
    expires_at: datetime = Field(description="상태 만료 일시 UTC")  # TTL. 이 시각이 지나면 조회에서 제외된다


class Severity(str, Enum):
    """인시던트의 심각도 등급. 대시보드에서 색상 구분에도 쓰인다."""
    CRITICAL = "CRITICAL"   # 빨강 - 즉시 대응
    HIGH = "HIGH"           # 주황 - 긴급
    MEDIUM = "MEDIUM"       # 노랑 - 주의
    LOW = "LOW"             # 초록 - 참고


class IncidentCategory(str, Enum):
    """
    침해사고의 유형 분류.

    NexusGuard가 주력으로 다루는 것은 SHADOW_AI_EXFILTRATION(섀도우 AI 유출)이고,
    나머지는 대시보드에 함께 보여주는 일반적인 보안 사고 유형이다.
    """
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"              # 외부 침투 및 내부 측면이동
    SHADOW_AI_EXFILTRATION = "SHADOW_AI_EXFILTRATION"  # 섀도우 AI 데이터 유출 ★ 주력 시나리오
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
    """인시던트 처리 진행 상태."""
    ACTIVE = "ACTIVE"          # 진행 중 (관리자 조치 대기)
    CONTAINED = "CONTAINED"    # 격리/대응 완료
    RESOLVED = "RESOLVED"      # 종료


class NetworkHop(BaseModel):
    """
    공격 경로의 한 구간. 이것들을 이어 붙이면 '킬체인'이 된다.

    예) 김대리 PC ─▶ 사내 DB ─▶ 외부 ChatGPT 서버
        이 경우 NetworkHop이 2개 만들어진다.

    대시보드의 '킬체인 분석' 화면에서 이 값들로 네트워크 토폴로지를 그린다.
    hop_type에 따라 선 색깔이 달라진다.
    """
    from_node: str = Field(description="출발지 (예: Internet, 203.0.113.10, Web Server)")
    to_node: str = Field(description="목적지 (예: Web Server, Internal Server, DB Server)")
    port: int = Field(description="통신 포트 (예: 443, 22, 3306)")
    hop_type: str = Field(default="suspicious", description="정상(normal), 의심(suspicious), 침투(attack)")


class Incident(BaseModel):
    """
    확정된 침해사고 한 건.

    상관분석 엔진이 위험을 확정하면 이 객체를 만들어 SQLite에 저장하고,
    대시보드가 이를 읽어 화면에 표시한다.

    evidences(근거 목록)가 특히 중요하다.
    "왜 이게 위험하다고 판단했는지"를 사람이 읽을 수 있게 배점과 함께 적어둔 것으로,
    관리자가 차단 여부를 직접 결정할 때 판단 재료가 된다.
    (NexusGuard는 시스템이 자동 차단하지 않는다. 결정은 사람이 한다.)
    """
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
    evidences: List[str] = Field(default_factory=list, description="상관분석 판단 근거 목록")  # 배점과 함께 사람이 읽을 수 있게 기록
    network_hops: List[NetworkHop] = Field(default_factory=list, description="재구성된 네트워크 경로")  # 킬체인 시각화에 사용
    soar_actions: List[str] = Field(default_factory=list, description="수행 가능한 자동 대응 조치")  # 시스템이 자동 실행하지 않고 관리자가 골라 실행한다


class SanctionStatus(str, Enum):
    """
    외부 AI 서비스에 대한 사내 승인 상태.

    NexusGuard의 거버넌스 철학: 무조건 막으면 직원들은 개인 폰/노트북으로 몰래 쓴다(풍선 효과).
    그래서 '차단'만이 아니라 '양성화(정식 승인)' 경로를 함께 제공한다.
    """
    APPROVED = "APPROVED"          # 정식 승인됨 (안전하게 써도 되는 도구)
    CONDITIONAL = "CONDITIONAL"    # 조건부 승인 (특정 부서만)
    UNAPPROVED = "UNAPPROVED"      # 미승인 (기본값. 감지는 됐으나 아직 심사 전)
    BLOCKED = "BLOCKED"            # 차단됨


class ShadowAIAsset(BaseModel):
    """
    사내에서 발견된 외부 AI/SaaS 서비스 하나.

    직원이 새 AI 사이트에 접속하면 이 자산이 자동 등록되고,
    Gemini가 해당 서비스의 이용약관·데이터 재학습 정책을 분석해 위험도를 매긴다.
    관리자는 이 목록을 보고 승인 / 대체재 안내 / 차단 중 하나를 고른다.
    """
    domain: str = Field(description="식별된 도메인 (예: chatgpt.com)")
    service_name: str = Field(description="서비스명 (예: ChatGPT)")
    category: str = Field(description="서비스 분류 (예: 생성형 AI, 파일 공유)")
    department_count: int = Field(description="사용 부서 수")
    user_count: int = Field(description="사용 임직원 수")
    usage_frequency: str = Field(description="사용 빈도 (매일, 주간 등)")
    risk_level: Severity = Field(description="자산 위험도 (HIGH, MEDIUM, LOW)")
    ai_diagnosis: str = Field(description="LLM 진단 소견 (데이터 학습 활용 여부 등)")
    sanction_status: SanctionStatus = Field(default=SanctionStatus.UNAPPROVED)  # 사내 승인 상태
    recommended_alternative: Optional[str] = Field(default=None, description="사내 권장 대체 도구")
    detected_at: datetime = Field(default_factory=datetime.now)  # 최초 감지 시각

    # [추가됨] 실시간 수집 연동용 두 필드.
    #   governance.sync_railway_events() 가 Railway 로그를 집계해서 채운다.
    #   access_count : 이 도메인에 누적 몇 번 접속했는지
    #   active_users : 실제로 접속한 사용자 이름 목록 (수집 전에는 "임직원 N명" 같은 시연값)
    #   기본값이 있으므로 이 필드를 모르는 예전 코드도 그대로 동작한다.
    access_count: int = Field(default=0, description="실시간 누적 접근 건수")
    active_users: List[str] = Field(default_factory=list, description="실시간 접속 사용자 목록")
