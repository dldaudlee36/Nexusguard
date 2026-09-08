"""
NexusGuard - Unified Security Event Schema
이기종 로그(DNS, Auth, Firewall, DB, Web)를 단일 표준으로 정규화하는 데이터 모델
"""

from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field


class LogSource(str, Enum):
    DNS = "dns"
    AUTH = "auth"
    FIREWALL = "firewall"
    DB = "db"
    WEB = "web"
    SYSTEM = "system"
    CHROME_EXTENSION = "chrome-extension"
    WINDOWS_AGENT = "windows-agent"


class EventAction(str, Enum):
    # Network / FW
    ALLOW = "ALLOW"
    DENY = "DENY"
    # DNS
    QUERY = "QUERY"
    # Auth
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILURE = "LOGIN_FAILURE"
    LOGOUT = "LOGOUT"
    # DB
    SELECT = "SELECT"
    INSERT = "INSERT"
    UPDATE = "UPDATE"
    DELETE = "DELETE"
    # Web / Proxy
    HTTP_GET = "HTTP_GET"
    HTTP_POST = "HTTP_POST"
    WEB_ACCESS = "WEB_ACCESS"
    FILE_UPLOAD_ATTEMPT = "FILE_UPLOAD_ATTEMPT"


class Actor(BaseModel):
    user_id: Optional[str] = Field(default=None, description="계정명 (예: admin, kim_marketing)")
    src_ip: str = Field(description="출발지 IP")
    src_port: Optional[int] = Field(default=None, description="출발지 포트")


class Target(BaseModel):
    dst_ip: Optional[str] = Field(default=None, description="목적지 IP")
    dst_port: Optional[int] = Field(default=None, description="목적지 포트 (예: 22, 443, 3306)")
    domain: Optional[str] = Field(default=None, description="도메인 주소 (예: chatgpt.com)")
    hostname: Optional[str] = Field(default=None, description="호스트명 (예: web-prod-01)")


class PayloadMetadata(BaseModel):
    query_string: Optional[str] = Field(default=None, description="SQL 쿼리 또는 HTTP URI")
    table_name: Optional[str] = Field(default=None, description="접근 테이블명 (예: customer_info)")
    rows_affected: Optional[int] = Field(default=None, description="영향받은 행 수")
    bytes_sent: Optional[int] = Field(default=None, description="전송 바이트 수")
    file_name: Optional[str] = Field(default=None, description="첨부/업로드 대상 파일명 (예: report.pdf, dump.zip)")
    file_size: Optional[int] = Field(default=None, description="첨부/업로드 파일 크기 (바이트)")
    category: Optional[str] = Field(default=None, description="서비스 카테고리 (예: Generative_AI, File_Sharing)")
    extra: Dict[str, Any] = Field(default_factory=dict, description="기타 확장 메타데이터")


class SecurityEvent(BaseModel):
    event_id: str = Field(description="고유 이벤트 ID (예: EVT-20260904-00108)")
    timestamp: datetime = Field(description="이벤트 발생 시각")
    log_source: LogSource = Field(description="원천 로그 종류")
    actor: Actor = Field(description="행위자 정보 (IP, 계정 등)")
    target: Target = Field(description="대상 정보 (IP, 포트, 도메인 등)")
    action: EventAction = Field(description="수행 행위")
    payload: PayloadMetadata = Field(default_factory=PayloadMetadata, description="페이로드 및 부가 정보")
    raw_message: Optional[str] = Field(default=None, description="원천 로그 텍스트")

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
