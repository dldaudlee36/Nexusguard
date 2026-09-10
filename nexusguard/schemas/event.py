"""
NexusGuard - Unified Security Event Schema
이기종 로그(DNS, Auth, Firewall, DB, Web)를 단일 표준으로 정규화하는 데이터 모델

[이 파일이 하는 일]
NexusGuard는 서로 다른 곳에서 로그를 받는다. 단말의 Windows Agent, Chrome 확장,
방화벽, DB 감사 로그... 각자 형식이 전부 다르다.
이 파일은 그 모든 로그를 SecurityEvent라는 하나의 형태로 통일한다.

이렇게 통일해두면 상관분석 엔진(engine/correlation.py)은
"이 로그가 어디서 왔는지" 신경 쓸 필요 없이 SecurityEvent 하나만 보면 된다.
새로운 로그 소스가 추가돼도 변환기(collectors/)만 만들면 엔진은 그대로 쓸 수 있다.

[구조]
SecurityEvent(하나의 사건)
  ├─ actor    : 누가 했나  (계정, 출발지 IP)
  ├─ target   : 어디에 했나 (목적지 IP/포트/도메인)
  ├─ action   : 무엇을 했나 (SELECT, WEB_ACCESS, FILE_UPLOAD_ATTEMPT ...)
  └─ payload  : 상세 내용   (쿼리문, 전송 바이트, 파일명 ...)
"""

from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field


class LogSource(str, Enum):
    """
    로그가 어느 장비/프로그램에서 왔는지 구분하는 값.

    엔진이 판정할 때 이 값을 함께 본다.
    예) 같은 '외부 전송'이라도 CHROME_EXTENSION에서 온 것은
        파일 첨부가 확실하므로 FIREWALL에서 온 것보다 점수가 높다.
        (engine/correlation.py 의 is_file_upload 판정 참고)
    """
    DNS = "dns"                             # DNS 질의 로그
    AUTH = "auth"                           # 로그인/로그아웃 등 인증 로그
    FIREWALL = "firewall"                   # 방화벽 통과/차단 로그
    DB = "db"                               # 데이터베이스 감사 로그 (SELECT 등)
    WEB = "web"                             # 웹 프록시 로그 (HTTP GET/POST)
    SYSTEM = "system"                       # 그 외 시스템 로그
    CHROME_EXTENSION = "chrome-extension"   # 크롬 확장 프로그램이 감지한 파일 첨부
    WINDOWS_AGENT = "windows-agent"         # 단말의 NexusGuardAgent.exe 가 감지한 접속


class EventAction(str, Enum):
    """
    사용자가 실제로 '무엇을 했는지'를 나타내는 값.

    상관분석에서 특히 중요한 세 가지:
      - SELECT              : 기밀 DB 조회 → WATCH 승격 조건 A
      - FILE_UPLOAD_ATTEMPT : 파일 첨부 시도 → HIGH 확정 조건
      - PASTE_ATTEMPT       : 대량 텍스트 붙여넣기 → WATCH 상태에서만 HIGH 확정 [추가됨]
    """
    # --- 네트워크 / 방화벽 ---
    ALLOW = "ALLOW"                                 # 방화벽 통과
    DENY = "DENY"                                   # 방화벽 차단

    # --- DNS ---
    QUERY = "QUERY"                                 # 도메인 이름 질의

    # --- 인증 ---
    LOGIN_SUCCESS = "LOGIN_SUCCESS"                 # 로그인 성공
    LOGIN_FAILURE = "LOGIN_FAILURE"                 # 로그인 실패 (연속 발생 시 무차별 대입 의심)
    LOGOUT = "LOGOUT"                               # 로그아웃

    # --- 데이터베이스 ---
    SELECT = "SELECT"                               # 조회 ★ 기밀 DB 조회 감지의 핵심
    INSERT = "INSERT"                               # 삽입
    UPDATE = "UPDATE"                               # 수정
    DELETE = "DELETE"                               # 삭제

    # --- 웹 / 프록시 ---
    HTTP_GET = "HTTP_GET"                           # 웹 조회
    HTTP_POST = "HTTP_POST"                         # 웹 전송 (대용량이면 유출 의심)
    WEB_ACCESS = "WEB_ACCESS"                       # 사이트 접속 (Agent가 DNS 캐시에서 감지)
    FILE_UPLOAD_ATTEMPT = "FILE_UPLOAD_ATTEMPT"     # 파일 첨부 시도 ★ 크롬 확장이 감지
    PASTE_ATTEMPT = "PASTE_ATTEMPT"                 # 대량 텍스트 붙여넣기 ★ 크롬 확장이 감지 [추가됨]


class Actor(BaseModel):
    """행위자 — '누가' 이 사건을 일으켰는가."""
    user_id: Optional[str] = Field(default=None, description="계정명 (예: admin, kim_marketing)")
    src_ip: str = Field(description="출발지 IP")
    src_port: Optional[int] = Field(default=None, description="출발지 포트")


class Target(BaseModel):
    """대상 — '어디에' 행위를 했는가. 내부 서버일 수도, 외부 사이트일 수도 있다."""
    dst_ip: Optional[str] = Field(default=None, description="목적지 IP")
    dst_port: Optional[int] = Field(default=None, description="목적지 포트 (예: 22, 443, 3306)")
    domain: Optional[str] = Field(default=None, description="도메인 주소 (예: chatgpt.com)")
    hostname: Optional[str] = Field(default=None, description="호스트명 (예: web-prod-01)")


class PayloadMetadata(BaseModel):
    """
    상세 내용 — 로그 종류마다 채워지는 항목이 다르다.

    DB 로그면 query_string / table_name / rows_affected 가 차고,
    파일 첨부 로그면 file_name / file_size 가 찬다.
    그래서 대부분의 항목이 Optional(없어도 됨)로 되어 있다.
    """
    query_string: Optional[str] = Field(default=None, description="SQL 쿼리 또는 HTTP URI")
    table_name: Optional[str] = Field(default=None, description="접근 테이블명 (예: customer_info)")
    rows_affected: Optional[int] = Field(default=None, description="영향받은 행 수")
    bytes_sent: Optional[int] = Field(default=None, description="전송 바이트 수")
    file_name: Optional[str] = Field(default=None, description="첨부/업로드 대상 파일명 (예: report.pdf, dump.zip)")
    file_size: Optional[int] = Field(default=None, description="첨부/업로드 파일 크기 (바이트)")
    category: Optional[str] = Field(default=None, description="서비스 카테고리 (예: Generative_AI, File_Sharing)")
    extra: Dict[str, Any] = Field(default_factory=dict, description="기타 확장 메타데이터")


class SecurityEvent(BaseModel):
    """
    정규화된 보안 이벤트 하나.

    NexusGuard 안을 돌아다니는 모든 로그는 결국 이 형태가 된다.
    수집기(collectors/)가 원본 로그를 이 형태로 바꾸고,
    엔진(engine/correlation.py)이 이것만 보고 위험도를 판정한다.
    """
    event_id: str = Field(description="고유 이벤트 ID (예: EVT-20260904-00108)")
    timestamp: datetime = Field(description="이벤트 발생 시각")
    log_source: LogSource = Field(description="원천 로그 종류")
    actor: Actor = Field(description="행위자 정보 (IP, 계정 등)")
    target: Target = Field(description="대상 정보 (IP, 포트, 도메인 등)")
    action: EventAction = Field(description="수행 행위")
    payload: PayloadMetadata = Field(default_factory=PayloadMetadata, description="페이로드 및 부가 정보")
    raw_message: Optional[str] = Field(default=None, description="원천 로그 텍스트")  # 사후 근거로 원본을 그대로 보존한다

    class Config:
        # datetime을 JSON으로 내보낼 때 ISO 문자열로 바꿔준다.
        # (SQLite 저장 및 대시보드 표시용)
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
