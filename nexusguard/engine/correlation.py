"""
NexusGuard - Multi-Dimensional Correlation Engine with Risk State Machine
2단계 위험 상태 기계(Risk State Machine) 기반 실시간 상관분석 & 인시던트 생성 엔진
"""

from typing import List, Dict, Optional, Any
from datetime import datetime, timedelta
import json

from nexusguard.schemas.event import SecurityEvent, LogSource, EventAction
from nexusguard.schemas.incident import (
    Incident, Severity, IncidentCategory, IncidentStatus, NetworkHop, RiskState
)
from nexusguard.engine.respond import on_risk_state_changed
from nexusguard.storage.sqlite_store import SQLiteStore

# 상태별 만료 주기 (TTL)
TTL = {
    "NORMAL": timedelta(minutes=0),
    "WATCH": timedelta(minutes=30),       # 30분 경과 시 오탐 자동 해제 (NORMAL 복귀)
    "HIGH": timedelta(hours=24),          # 24시간 유지
    "CRITICAL": timedelta(days=7)
}

SENSITIVE_TABLES = {"customer_info", "customer_vault", "corp_strategic_plan", "salary_2026", "secret_key"}
KNOWN_AI_DOMAINS = {"chatgpt.com", "api.openai.com", "claude.ai", "wetransfer.com", "dropbox.com"}


class CorrelationEngine:
    """2단계 위험 상태 기계 기반 이기종 보안 이벤트 상관분석 코어 엔진"""

    def __init__(self, time_window_minutes: int = 15, enable_mock_incidents: bool = True):
        self.time_window = timedelta(minutes=time_window_minutes)
        self.event_buffer: List[SecurityEvent] = []
        self.incidents: Dict[str, Incident] = {}
        self.store = SQLiteStore()
        
        # 사용자별 최근 민감 행위 메모리 캐시 (DB 조회 기록 등)
        self.user_sensitive_db_touch: Dict[str, datetime] = {}
        self.user_visited_unapproved_ai: Dict[str, Dict[str, Any]] = {}

        if enable_mock_incidents:
            self._init_mock_incidents()
        
        # SQLite에서 기존 저장된 인시던트 로드
        persisted = self.store.get_all_incidents()
        for inc in persisted:
            self.incidents[inc.incident_id] = inc

    def _init_mock_incidents(self):
        """사전 등록된 기준 인시던트 데이터 초기화 (하위 호환성 유지)"""
        # INC-001 (CRITICAL: 금융 고객 개인정보 2.4만 건 대량 탈취 및 C2 유출)
        inc_1 = Incident(
            incident_id="INC-001",
            title="금융 고객 개인정보 2.4만 건 대량 탈취 및 C2 비정상 유출",
            category=IncidentCategory.LATERAL_MOVEMENT,
            severity=Severity.CRITICAL,
            score=96,
            status=IncidentStatus.ACTIVE,
            summary="외부 무차별 대입 후 웹서버 로그인 -> 내부 SSH(:22) 피보팅 -> 고객정보 24,500건 덤프 후 외부 C2(:10443) 158MB 유출",
            actor="203.116.45.23 (admin 계정 탈취)",
            target_asset="DB Server (10.0.0.30:3306 / customer_vault)",
            created_at=datetime.utcnow() - timedelta(minutes=7),
            event_ids=["EVT-A-100", "EVT-A-101", "EVT-A-105", "EVT-A-107", "EVT-A-108", "EVT-A-109", "EVT-A-110"],
            evidences=[
                "동일 계정(admin) 세션 연속 악용 (+2점)",
                "IP 홉 연속 체인: 203.116.45.23 -> 10.0.0.10:443 -> 10.0.0.20:22 -> 10.0.0.30:3306 (+2점)",
                "전체 침해 행위 5분 10초 이내 연속 발생 (10분 윈도우 기준 충족, +2점)",
                "공격 킬체인 시퀀스 100% 부합 (브루트포스 -> 성공 -> SSH 피보팅 -> DB 덤프 -> C2 유출, +4점)"
            ],
            network_hops=[
                NetworkHop(from_node="Internet (203.116.45.23)", to_node="Web Server (10.0.0.10)", port=443, hop_type="attack"),
                NetworkHop(from_node="Web Server (10.0.0.10)", to_node="Internal Server (10.0.0.20)", port=22, hop_type="lateral"),
                NetworkHop(from_node="Internal Server (10.0.0.20)", to_node="DB Server (10.0.0.30)", port=3306, hop_type="db_access"),
                NetworkHop(from_node="Internal Server (10.0.0.20)", to_node="External C2 (203.116.45.23)", port=10443, hop_type="exfiltration"),
            ],
            soar_actions=[
                "방화벽 출발지 IP(203.116.45.23) 영구 차단 룰 적용",
                "admin 계정 활성 세션 즉시 강제 종료(Revoke)",
                "내부 서버(10.0.0.20) SSH 접근 포트 임시 격리"
            ]
        )

        # INC-002 (HIGH: 마케팅팀 미승인 생성형 AI를 통한 전략기획서 유출 의심)
        inc_2 = Incident(
            incident_id="INC-002",
            title="마케팅팀 미승인 생성형 AI(ChatGPT)를 통한 신규 전략기획서 유출 의심",
            category=IncidentCategory.SHADOW_AI_EXFILTRATION,
            severity=Severity.HIGH,
            score=91,
            status=IncidentStatus.ACTIVE,
            summary="사내 DB에서 전략기획서 SELECT 직후 110초 내 chatgpt.com DNS 질의 및 1.45MB API 업로드 발생",
            actor="192.168.10.45 (kim_marketing)",
            target_asset="corp_strategic_plan -> chatgpt.com",
            created_at=datetime.utcnow() - timedelta(minutes=4),
            event_ids=["EVT-B-201", "EVT-B-202", "EVT-B-203"],
            evidences=[
                "동일 호스트/계정 행위: 192.168.10.45 (kim_marketing) (+2점)",
                "사내 기밀 DB 조회 후 145초 이내 미승인 AI(chatgpt.com) 접근 (+2점)",
                "일반 웹 서핑 대비 비정상적 업로드 볼륨: 1.45 MB 전송 (+2점)",
                "데이터 유출 시퀀스 부합 (민감 데이터 SELECT -> AI DNS 질의 -> POST 전송, +4점)"
            ],
            network_hops=[
                NetworkHop(from_node="Employee PC (192.168.10.45)", to_node="DB Server (10.0.0.30)", port=3306, hop_type="db_access"),
                NetworkHop(from_node="Employee PC (192.168.10.45)", to_node="DNS Server (10.0.0.5)", port=53, hop_type="normal"),
                NetworkHop(from_node="Employee PC (192.168.10.45)", to_node="OpenAI Cloud (chatgpt.com)", port=443, hop_type="suspicious"),
            ],
            soar_actions=[
                "임직원(kim_marketing) 대상 사내 보안 포털 경고 알림 발송",
                "사내 프라이빗 AI(Aegis-GenAI) 사용 유도 가이드 전달",
                "보안팀 인가 심의 티켓 자동 등록 (양성화 워크플로)"
            ]
        )

        # INC-003 (NORMAL / MEDIUM: 사내 정규 협업 SaaS 정상 트래픽 및 정기 보안 정책 준수)
        inc_3 = Incident(
            incident_id="INC-003",
            title="사내 정규 협업 SaaS(Slack/Zoom) 정상 트래픽 및 보안 정책 준수",
            category=IncidentCategory.INSIDER_DATA_THEFT,
            severity=Severity.MEDIUM,
            score=45,
            status=IncidentStatus.ACTIVE,
            summary="사내 업무 목적 정규 클라우드 협업 도구 연동 트래픽으로 보안 이상 징후 없음 (정상 모니터링 단계)",
            actor="192.168.10.15 (jung_sales)",
            target_asset="Workplace SaaS -> api.slack.com",
            created_at=datetime.utcnow() - timedelta(hours=1),
            event_ids=["EVT-C-301", "EVT-C-302"],
            evidences=[
                "사내 결재 승인 소프트웨어 라이선스 보유 (+0점)",
                "정상 업무 시간대 아웃바운드 세션 발생 (+0점)",
                "단말 무결성 검증 통과 (+0점)"
            ],
            network_hops=[
                NetworkHop(from_node="Employee PC (192.168.10.15)", to_node="Internal Gateway", port=443, hop_type="normal"),
                NetworkHop(from_node="Internal Gateway", to_node="Cloud (api.slack.com)", port=443, hop_type="normal"),
            ],
            soar_actions=[
                "정기 접속 감사 로그 아카이빙",
                "사내 보안 정책 기준 정상 세션 유지"
            ]
        )

        # INC-004 (WATCH / LOW: 인사팀 단말의 비인가 내부 서브넷 탐색 및 사전 관찰 대상 등록)
        inc_4 = Incident(
            incident_id="INC-004",
            title="인사팀 단말의 비인가 내부 서브넷 탐색 징후 및 사전 관찰 대상(WATCH) 등록",
            category=IncidentCategory.UNAUTHORIZED_PORT,
            severity=Severity.LOW,
            score=65,
            status=IncidentStatus.ACTIVE,
            summary="단말에서 비인가 내부 세그먼트 포트 질의가 포착되어 1단계 사전 감시(WATCH) 대상으로 등록됨",
            actor="192.168.10.12 (kang_hr)",
            target_asset="10.0.0.0/24 Core Segment",
            created_at=datetime.utcnow() - timedelta(minutes=15),
            event_ids=["EVT-D-401"],
            evidences=[
                "업무 범위를 벗어난 내부 서브넷 SYN 스캔 포착 (+2점)",
                "1단계 선제 감시: 위험 행위 사전 관찰(WATCH) 상태 자동 등록 (+4점)"
            ],
            network_hops=[
                NetworkHop(from_node="HR PC (192.168.10.12)", to_node="Internal Core Segment", port=445, hop_type="suspicious"),
            ],
            soar_actions=[
                "단말 내부 세션 실시간 패킷 모니터링 강화",
                "사용자 계정 상태 사전 감시(WATCH) 플래그 설정"
            ]
        )

        for inc in [inc_1, inc_2, inc_3, inc_4]:
            self.incidents[inc.incident_id] = inc

    def ingest_events(self, events: List[SecurityEvent]):
        """이벤트 버퍼에 이벤트 추가 및 상태 기계 상관분석 수행"""
        self.event_buffer.extend(events)
        # 이벤트 timestamp 기준 정렬 (도착 역순 보정)
        self.event_buffer.sort(key=lambda e: e.timestamp)
        
        for ev in events:
            self.update_user_risk(ev)

    def update_user_risk(self, event: SecurityEvent) -> None:
        """
        단일 이벤트에 대한 2단계 위험 상태 기계(State Machine) 전이 처리
        1. 전송 전 조건(민감 DB 조회 + 미승인 AI 질의) -> WATCH 승격 & 1차 알림
        2. WATCH 상태에서 외부 전송 발생 -> HIGH Incident 확정 & 2차 알림
        """
        user = event.actor.user_id or event.actor.src_ip
        now_utc = datetime.utcnow()

        # 1. 만료 시각(expires_at > now) 기준 현재 유효 상태 조회
        current_risk = self.store.get_active_risk(user)
        old_state = current_risk["state"] if current_risk else "NORMAL"

        # 2. 행위 특징 분석 (DB, DNS/Web, Firewall)
        # 2.1 DB 조회 행위 포착
        if event.log_source == LogSource.DB and event.action == EventAction.SELECT:
            tbl = event.payload.table_name or ""
            query = event.payload.query_string or ""
            if tbl in SENSITIVE_TABLES or any(k in query.lower() for k in ["customer", "secret", "vault", "plan"]):
                self.user_sensitive_db_touch[user] = event.timestamp
                return

        # 2.2 미승인 AI / 외부 SaaS 접근 포착
        target_domain = event.target.domain or ""
        is_ai_or_cloud = target_domain in KNOWN_AI_DOMAINS or "ai" in target_domain or "transfer" in target_domain
        if (event.log_source in [LogSource.DNS, LogSource.WEB]) and is_ai_or_cloud:
            self.user_visited_unapproved_ai[user] = {
                "domain": target_domain,
                "time": event.timestamp
            }
            # 민감 DB 조회가 선행되었는지 확인 (15분 이내)
            db_touch_time = self.user_sensitive_db_touch.get(user)
            if db_touch_time and (event.timestamp - db_touch_time) <= timedelta(minutes=15):
                # 🌟 [1단계] WATCH 상태 전이 (전송 이전 선제 감시)
                new_state = "WATCH"
                score = 68
                reasons = [
                    f"사내 기밀 DB({event.actor.user_id or '단말'}) SELECT 조회 선행",
                    f"15분 내 미승인 외부 서비스({target_domain}) 접근 포착",
                    "데이터 외부 반출 위험으로 사전 감시 승격"
                ]
                self._apply_state_transition(user, old_state, new_state, score, reasons, event)
                return

        # 2.3 외부 데이터 전송 발생 포착 (Firewall ALLOW / Web POST)
        bytes_out = event.payload.bytes_sent or 0
        is_exfil = (
            (event.log_source == LogSource.FIREWALL and event.action == EventAction.ALLOW and bytes_out > 50000) or
            (event.log_source == LogSource.WEB and event.action == EventAction.HTTP_POST and bytes_out > 50000)
        )

        if is_exfil:
            # 사용자가 현재 WATCH 상태인 경우 -> 🌟 [2단계] HIGH Incident 확정!
            if old_state == "WATCH":
                new_state = "HIGH"
                score = 92
                reasons = [
                    "사전 감시(WATCH) 등록 사용자의 외부 대용량 데이터 전송 감지",
                    f"전송 볼륨: {bytes_out / (1024*1024):.2f} MB",
                    "민감정보 외부 반출 킬체인 시퀀스 100% 충족"
                ]
                
                # 동적 Incident 생성
                inc = self._create_dynamic_incident(user, event, bytes_out)
                self._apply_state_transition(user, old_state, new_state, score, reasons, event, incident=inc)
                return

    def _apply_state_transition(self, user: str, old_state: str, new_state: str,
                                score: int, reasons: List[str], event: SecurityEvent, incident=None):
        now_utc = datetime.utcnow()
        expires_at = now_utc + TTL.get(new_state, timedelta(hours=1))

        # 중복 알림 억제: 상태가 동일하면 만료 시간만 연장
        if new_state == old_state:
            self.store.extend_expiry(user, expires_at)
            return

        # 상태 갱신 및 이력 적재
        self.store.upsert_risk(user, new_state, score, reasons, expires_at)
        self.store.append_history(user, old_state, new_state, " / ".join(reasons))

        # SOAR 알림 훅 호출
        on_risk_state_changed(user, old_state, new_state, reasons, incident)

    def _create_dynamic_incident(self, user: str, event: SecurityEvent, bytes_out: int) -> Incident:
        inc_id = f"INC-SEC-{len(self.incidents) + 1:03d}"
        target_domain = event.target.domain or event.target.dst_ip or "external-cloud"
        
        inc = Incident(
            incident_id=inc_id,
            title=f"사용자 '{user}' 미승인 서비스({target_domain})를 통한 기밀 데이터 유출 확정",
            category=IncidentCategory.SHADOW_AI_EXFILTRATION,
            severity=Severity.HIGH,
            score=92,
            status=IncidentStatus.ACTIVE,
            summary=f"기밀 DB 조회 후 미승인 사이트({target_domain})로 {bytes_out / (1024*1024):.2f}MB 대용량 외부 전송이 발생하여 2단계 상관분석으로 HIGH Incident 생성",
            actor=f"{event.actor.src_ip} ({user})",
            target_asset=f"Core DB -> {target_domain}",
            created_at=datetime.utcnow(),
            event_ids=[event.event_id],
            evidences=[
                f"동일 사용자/단말({user}) 행위 체인 100% 일치 (+2점)",
                f"기밀 DB 조회 직후 15분 내 미승인 서비스({target_domain}) 접근 (+2점)",
                f"위험 상태 기계: WATCH 상태에서 외부 대용량 전송({bytes_out / 1024:.1f} KB) 감지 (+4점)",
                "동적 2단계 유출 상관분석 시퀀스 최종 완성 (+2점)"
            ],
            network_hops=[
                NetworkHop(from_node=f"User PC ({event.actor.src_ip})", to_node="Internal DB", port=3306, hop_type="db_access"),
                NetworkHop(from_node=f"User PC ({event.actor.src_ip})", to_node=f"Cloud ({target_domain})", port=443, hop_type="attack")
            ],
            soar_actions=[
                f"단말({event.actor.src_ip}) 외부 아웃바운드 세션 일시 차단",
                f"계정({user}) MFA 재인증 요구 및 세션 감사",
                "사내 보안팀 긴급 슬랙 알림 웹훅 발행 완료"
            ]
        )
        self.incidents[inc_id] = inc
        self.store.save_incident(inc)
        return inc

    def create_watch_incident(self, user: str, sc: Dict[str, Any]) -> Incident:
        """1단계 선제 감시(WATCH) 인시던트 생성 및 등록"""
        inc_id = f"INC-WATCH-{len(self.incidents) + 1:03d}"
        now = datetime.utcnow()
        inc = Incident(
            incident_id=inc_id,
            title=f"사용자 '{user}' 미승인 AI 접속 및 기밀 반출 위험 선제 감시 (WATCH)",
            category=IncidentCategory.SHADOW_AI_EXFILTRATION,
            severity=Severity.LOW,
            score=68,
            status=IncidentStatus.ACTIVE,
            summary=f"사내 기밀 DB({sc.get('table', 'vault')}) 조회 후 15분 내 미승인 서비스({sc.get('service', 'AI')}) 접속 포착 — 데이터 외부 반출 전 선제 감시(WATCH) 승격",
            actor=f"{sc.get('ip', '192.168.10.x')} ({user})",
            target_asset=f"Core DB -> {sc.get('service', 'external-ai')}",
            created_at=now,
            event_ids=[f"EVT-WATCH-{int(now.timestamp())}"],
            evidences=[
                f"사내 기밀 DB({sc.get('table', 'vault')}) SELECT 조회 선행 (+2점)",
                f"15분 내 미승인 외부 서비스({sc.get('service', 'AI')}) 접속 (+2점)",
                "위험 상태 기계: 1단계 사전 감시(WATCH) 승격 완료 (+4점)"
            ],
            network_hops=[
                NetworkHop(from_node=f"User PC ({sc.get('ip', '192.168.10.x')})", to_node="Internal DB", port=3306, hop_type="db_access"),
                NetworkHop(from_node=f"User PC ({sc.get('ip', '192.168.10.x')})", to_node=f"Cloud ({sc.get('service', 'external-ai')})", port=443, hop_type="suspicious")
            ],
            soar_actions=[
                f"단말({sc.get('ip', '192.168.10.x')}) 아웃바운드 트래픽 정밀 감시(DPI)",
                f"사용자({user}) 세션 선제 감시 플래그 점등",
                "사내 보안팀 1차 선제 감시 알림 전파"
            ]
        )
        self.incidents[inc_id] = inc
        self.store.save_incident(inc)
        return inc

    def create_heal_incident(self, user: str) -> Incident:
        """3단계 오탐 자가 치유(NORMAL) 인시던트 생성 및 등록"""
        inc_id = f"INC-NORM-{len(self.incidents) + 1:03d}"
        now = datetime.utcnow()
        inc = Incident(
            incident_id=inc_id,
            title=f"사용자 '{user}' 30분 무전송 만료(TTL)로 인한 정상(NORMAL) 자가 치유",
            category=IncidentCategory.INSIDER_DATA_THEFT,
            severity=Severity.MEDIUM,
            score=20,
            status=IncidentStatus.RESOLVED,
            summary=f"사전 감시(WATCH) 대상자였으나 30분간 추가 외부 데이터 전송이 발생하지 않아 정상(NORMAL) 상태로 안전하게 자가 치유(Self-healing) 완료",
            actor=f"Internal ({user})",
            target_asset=f"Audited Asset ({user})",
            created_at=now,
            event_ids=[f"EVT-TTL-{int(now.timestamp())}"],
            evidences=[
                "사전 감시 등록 후 30분간 외부 대용량 전송 무발생 (+0점)",
                "Self-Healing TTL 정책에 따른 안전한 NORMAL 자동 복귀 (+0점)"
            ],
            network_hops=[
                NetworkHop(from_node=f"User PC ({user})", to_node="Internal Gateway", port=443, hop_type="normal")
            ],
            soar_actions=[
                "선제 감시(WATCH) 플래그 정상 해제",
                "SQLite 상태 전이 감사 로그 영구 기록 완료"
            ]
        )
        self.incidents[inc_id] = inc
        self.store.save_incident(inc)
        return inc

    def get_all_incidents(self) -> List[Incident]:
        return sorted(list(self.incidents.values()), key=lambda x: x.created_at, reverse=True)

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        return self.incidents.get(incident_id)

    def get_watch_users(self) -> List[Dict[str, Any]]:
        """현재 WATCH 상태에 있는 감시 대상자 목록 반환"""
        return self.store.get_all_active_risks()

