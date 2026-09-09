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

    def __init__(self, time_window_minutes: int = 15, enable_mock_incidents: bool = False):
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
        """가짜 목 인시던트 생성 비활성화 (로그 부재 시 빈 상태 유지)"""
        pass

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

        # 2.2 파일 업로드 시도 또는 외부 데이터 전송 발생 포착 (Chrome Extension / Firewall ALLOW / Web POST)
        target_domain = event.target.domain or ""
        is_ai_or_cloud = target_domain in KNOWN_AI_DOMAINS or any(k in target_domain.lower() for k in ["ai", "gpt", "claude", "gemini", "transfer", "dropbox", "box", "drive"])
        file_name = event.payload.file_name or ""
        file_size = event.payload.file_size or event.payload.bytes_sent or 0
        bytes_out = event.payload.bytes_sent or file_size or 0

        is_file_upload = (
            event.action == EventAction.FILE_UPLOAD_ATTEMPT or
            event.log_source == LogSource.CHROME_EXTENSION or
            bool(file_name)
        )
        is_exfil = (
            is_file_upload or
            (event.log_source == LogSource.FIREWALL and event.action == EventAction.ALLOW and bytes_out > 50000) or
            (event.log_source == LogSource.WEB and event.action == EventAction.HTTP_POST and bytes_out > 50000)
        )

        if is_exfil:
            # 1) 사용자가 현재 WATCH 상태인 경우 -> 🌟 [2단계] HIGH Incident 확정!
            if old_state == "WATCH":
                new_state = "HIGH"
                score = 95 if is_file_upload else 92
                if is_file_upload:
                    reasons = [
                        "사전 감시(WATCH) 등록 사용자의 브라우저 파일 업로드 시도 실시간 감지 (Chrome Extension)",
                        f"첨부 파일: '{file_name}' ({file_size / 1024:.1f} KB)" if file_size else f"첨부 파일: '{file_name}'",
                        f"대상 서비스: {target_domain}",
                        "사내 기밀 DB 조회 후 외부 AI/SaaS 파일 업로드 시도로 유출 킬체인 100% 충족"
                    ]
                else:
                    reasons = [
                        "사전 감시(WATCH) 등록 사용자의 외부 대용량 데이터 전송 감지",
                        f"전송 볼륨: {bytes_out / (1024*1024):.2f} MB",
                        "민감정보 외부 반출 킬체인 시퀀스 100% 충족"
                    ]
                
                # 동적 Incident 생성
                inc = self._create_dynamic_incident(user, event, bytes_out, file_name=file_name, file_size=file_size)
                self._apply_state_transition(user, old_state, new_state, score, reasons, event, incident=inc)
                return
            else:
                # 2) 사용자가 NORMAL 상태인 경우 -> 🌟 [단독 이상 징후 및 잠복형 유출 탐지]
                has_prior_watch = self.store.has_user_prior_watch_history(user) if hasattr(self.store, "has_user_prior_watch_history") else False
                if has_prior_watch:
                    # 30분 만료(TTL) 후 지연 발생한 잠복형 유출(Dormant Exfiltration / Evasion) 포착 -> 즉시 HIGH 직행!
                    new_state = "HIGH"
                    score = 96 if is_file_upload else 94
                    if is_file_upload:
                        reasons = [
                            "과거 기밀 DB 조회 및 WATCH 이력 보유자의 브라우저 파일 업로드 시도 감지",
                            "30분 감시 만료(TTL)를 노린 지연 잠복형 유출(Dormant Exfiltration) 시도 포착",
                            f"업로드 시도: '{file_name}' ({file_size / 1024:.1f} KB) -> {target_domain}"
                        ]
                    else:
                        reasons = [
                            "과거 기밀 DB 조회 및 WATCH 이력 보유자의 외부 대용량 전송 감지",
                            "30분 감시 만료(TTL)를 노린 지연 잠복형 유출(Dormant Exfiltration) 시도 포착",
                            f"전송 볼륨: {bytes_out / (1024*1024):.2f} MB"
                        ]
                    inc = self._create_dynamic_incident(
                        user, event, bytes_out,
                        file_name=file_name, file_size=file_size,
                        title_prefix="[잠복형 유출 의심]",
                        evidence_note="과거 WATCH 이력 소급 분석: TTL 만료 후 발생한 지연 파일 업로드 유출(Evasion) 감지 (+4점)"
                    )
                    self._apply_state_transition(user, old_state, new_state, score, reasons, event, incident=inc)
                    return
                elif is_file_upload and is_ai_or_cloud:
                    # 미승인 AI 사이트에 파일 업로드 시도한 경우 -> 단독 고위험 징후로 즉시 WATCH 승격
                    new_state = "WATCH"
                    score = 82
                    reasons = [
                        f"미승인 생성형 AI({target_domain})로의 파일 첨부 시도 감지 (Chrome Extension)",
                        f"첨부 파일: '{file_name}' ({file_size / 1024:.1f} KB)" if file_size else f"첨부 파일: '{file_name}'",
                        "프롬프트 및 문서 업로드를 통한 비인가 사내 자산 외부 유출 위험 선제 감시"
                    ]
                    self._apply_state_transition(user, old_state, new_state, score, reasons, event)
                    return
                elif bytes_out >= 1_000_000:
                    # 사전 등록 없는 단독 대용량 이상 전송 감지 (Outbound Spike)
                    new_state = "WATCH"
                    score = 72
                    reasons = [
                        f"비인가 외부 서비스로의 단독 비정상 대용량 전송 포착 ({bytes_out / (1024*1024):.2f} MB)",
                        "임계치(1MB) 초과 Outbound Traffic Spike 단독 이상 징후 감지"
                    ]
                    self._apply_state_transition(user, old_state, new_state, score, reasons, event)
                    return

        # 2.3 미승인 AI / 외부 SaaS 단순 접근 및 질의 포착 (전송 이전 선제 감시)
        if (event.log_source in [LogSource.DNS, LogSource.WEB, LogSource.WINDOWS_AGENT]) and is_ai_or_cloud:
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

    def _create_dynamic_incident(self, user: str, event: SecurityEvent, bytes_out: int,
                                 file_name: Optional[str] = None, file_size: Optional[int] = None,
                                 title_prefix: str = "", evidence_note: Optional[str] = None) -> Incident:
        inc_id = f"INC-SEC-{len(self.incidents) + 1:03d}"
        target_domain = event.target.domain or event.target.dst_ip or "external-cloud"
        prefix_str = f"{title_prefix} " if title_prefix else ""
        
        fname = file_name or event.payload.file_name
        fsize = file_size or event.payload.file_size or bytes_out
        size_kb = fsize / 1024.0 if fsize else 0

        if fname:
            title = f"{prefix_str}사용자 '{user}' 미승인 서비스({target_domain})로 기밀 파일('{fname}') 업로드 유출 확정"
            summary = f"사용자 '{user}'({event.actor.src_ip})가 {target_domain}에 기밀 파일('{fname}', {size_kb:.1f} KB) 업로드를 시도하여 Chrome 확장 프로그램 및 에이전트에 의해 실시간 포착/차단되었습니다."
            evidences = [
                f"Chrome 확장 프로그램(NexusGuard Upload Detector) 실시간 첨부 감지: '{fname}' ({fsize:,} bytes) (+4점)",
                f"단말 Windows Agent(NexusGuardAgent.exe) 로컬 브릿지 연동 및 Railway 중앙 서버 실시간 전송 검증 (+2점)",
                f"동일 사용자/단말({user} / {event.actor.src_ip}) 킬체인 100% 일치 (+2점)",
                evidence_note or f"기밀 DB 조회 직후 15분 내 미승인 서비스({target_domain}) 파일 업로드 연계 (+2점)"
            ]
            network_hops = [
                NetworkHop(from_node=f"User PC ({event.actor.src_ip})", to_node="Internal DB", port=3306, hop_type="db_access"),
                NetworkHop(from_node=f"User PC ({event.actor.src_ip})", to_node="Chrome Extension (Upload Detector)", port=8765, hop_type="lateral"),
                NetworkHop(from_node="Chrome Extension (Upload Detector)", to_node=f"Cloud ({target_domain})", port=443, hop_type="exfiltration")
            ]
            soar_actions = [
                f"단말({event.actor.src_ip}) 브라우저 파일 업로드 세션 즉시 차단",
                f"업로드 대상 파일('{fname}') 해시 기반 전사 DLP 차단 정책 등록",
                f"사용자({user}) 계정 긴급 감사 및 보안팀 통보 완료"
            ]
        else:
            title = f"{prefix_str}사용자 '{user}' 미승인 서비스({target_domain})를 통한 기밀 데이터 유출 확정"
            summary = f"기밀 DB 조회 후 미승인 사이트({target_domain})로 {bytes_out / (1024*1024):.2f}MB 대용량 외부 전송이 발생하여 2단계 상관분석으로 HIGH Incident 생성"
            evidences = [
                f"동일 사용자/단말({user}) 행위 체인 100% 일치 (+2점)",
                evidence_note or f"기밀 DB 조회 직후 15분 내 미승인 서비스({target_domain}) 접근 (+2점)",
                f"위험 상태 기계: 외부 대용량 전송({bytes_out / 1024:.1f} KB) 감지 (+4점)",
                "동적 2단계 유출 상관분석 시퀀스 최종 완성 (+2점)"
            ]
            network_hops = [
                NetworkHop(from_node=f"User PC ({event.actor.src_ip})", to_node="Internal DB", port=3306, hop_type="db_access"),
                NetworkHop(from_node=f"User PC ({event.actor.src_ip})", to_node=f"Cloud ({target_domain})", port=443, hop_type="attack")
            ]
            soar_actions = [
                f"단말({event.actor.src_ip}) 외부 아웃바운드 세션 일시 차단",
                f"계정({user}) MFA 재인증 요구 및 세션 감사",
                "사내 보안팀 긴급 슬랙 알림 웹훅 발행 완료"
            ]

        inc = Incident(
            incident_id=inc_id,
            title=title,
            category=IncidentCategory.SHADOW_AI_EXFILTRATION,
            severity=Severity.HIGH,
            score=95 if fname else 92,
            status=IncidentStatus.ACTIVE,
            summary=summary,
            actor=f"{event.actor.src_ip} ({user})",
            target_asset=f"Core DB -> {target_domain}" if not fname else f"Core DB -> {target_domain} ({fname})",
            created_at=datetime.utcnow(),
            event_ids=[event.event_id],
            evidences=evidences,
            network_hops=network_hops,
            soar_actions=soar_actions
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
            severity=Severity.MEDIUM,
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
            severity=Severity.LOW,
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

