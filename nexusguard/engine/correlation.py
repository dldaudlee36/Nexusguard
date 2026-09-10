"""
NexusGuard - Multi-Dimensional Correlation Engine with Risk State Machine
2단계 위험 상태 기계(Risk State Machine) 기반 실시간 상관분석 & 인시던트 생성 엔진

=====================================================================
[이 파일이 NexusGuard의 심장이다]
=====================================================================

들어온 로그(SecurityEvent) 하나하나를 보고
"이 사용자를 어떤 위험 상태로 둘 것인가"를 판정한다.

[핵심 아이디어 — 왜 2단계인가]
기존 보안 장비는 데이터가 다 빠져나간 뒤에야 경보를 울린다(사후 약방문).
NexusGuard는 그 전에 한 번 더 끊어서 본다.

  1단계 WATCH : 아직 데이터는 안 나갔다. 하지만 '나갈 준비'를 하는 정황이 보인다.
                → 관리자에게 1차 주의 알림
  2단계 HIGH  : 실제로 데이터가 나갔다.
                → 관리자에게 2차 긴급 알림 + 인시던트 확정

비유하면, 은행원이 금고에서 현금다발을 꺼내(기밀 DB 조회)
바로 뒷골목 불법 환전소 문을 열고 들어갔다(미승인 AI 접속).
아직 돈을 건네지 않았어도 경비원은 이 사람을 요주의 인물로 등록해야 한다. 그게 WATCH다.

[상태 전이 규칙 요약]
  NORMAL ──(기밀DB 조회 + 15분 내 미승인 AI 접속)──▶ WATCH   68점
  WATCH  ──(외부 전송 발생)────────────────────────▶ HIGH    92~95점
  WATCH  ──(30분간 전송 없음, TTL 만료)────────────▶ NORMAL  자가 치유
  NORMAL ──(단독 대용량 전송 + 과거 WATCH 이력)────▶ HIGH    잠복형 유출

[중요한 설계 원칙]
  · WATCH 승격은 조건을 '모두' 만족했을 때만 한다. 하나만 걸려서는 올리지 않는다.
  · 모든 상태에는 TTL(만료 시간)을 건다. 영원히 감시받는 사람이 있어서는 안 된다.
  · 이 엔진은 차단하지 않는다. 판정하고 알릴 뿐이고, 차단은 관리자가 직접 한다.

[읽는 순서 추천]
  update_user_risk()  ← 판정 로직 전체. 여기부터 보면 된다
  _apply_state_transition()  ← 판정 결과를 저장하고 알림을 쏘는 곳
  _create_dynamic_incident() ← HIGH 확정 시 인시던트를 만드는 곳
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
# 이 시간이 지나면 해당 상태는 조회에서 제외되어 자동으로 NORMAL로 취급된다.
# WATCH를 30분으로 잡은 이유: 단순 질문만 하고 나간 사람을 계속 감시하면
# 관제사에게 쓸모없는 알람만 쌓이기 때문(Alert Fatigue).
TTL = {
    "NORMAL": timedelta(minutes=0),
    "WATCH": timedelta(minutes=30),       # 30분 경과 시 오탐 자동 해제 (NORMAL 복귀)
    "HIGH": timedelta(hours=24),          # 24시간 유지
    "CRITICAL": timedelta(days=7)
}

# 기밀 테이블 목록 — 이 테이블을 조회하면 WATCH 승격 조건 A가 성립한다.
# ※ 지금은 코드에 고정되어 있다. 실제 운영에서는 설정 파일이나 DB로 빼는 것이 좋다.
SENSITIVE_TABLES = {"customer_info", "customer_vault", "corp_strategic_plan", "salary_2026", "secret_key"}

# 미승인 외부 AI/파일공유 도메인 목록 — 여기 접속하면 WATCH 승격 조건 B가 성립한다.
# ※ 아래 update_user_risk() 에서는 이 목록에 없어도 도메인 이름에 'ai', 'gpt' 등이
#   들어 있으면 같은 취급을 한다(신규 AI 사이트가 계속 생기기 때문).
KNOWN_AI_DOMAINS = {"chatgpt.com", "api.openai.com", "claude.ai", "wetransfer.com", "dropbox.com"}


class CorrelationEngine:
    """
    2단계 위험 상태 기계 기반 이기종 보안 이벤트 상관분석 코어 엔진

    '상관분석(Correlation)'이란 로그 하나만 보지 않고
    여러 로그를 시간 축으로 엮어서 의미를 찾아내는 것을 말한다.

    예) "DB를 조회했다"  → 그 자체로는 정상 업무
        "ChatGPT에 접속했다" → 그 자체로도 정상 업무
        "DB 조회하고 5분 뒤 ChatGPT 접속" → 이건 유출 준비 정황
    """

    def __init__(self, time_window_minutes: int = 15, enable_mock_incidents: bool = True):
        """
        time_window_minutes: 두 행위를 '연관 있다'고 볼 시간 범위 (기본 15분)
                             DB 조회 후 15분 안에 AI 접속해야 WATCH로 올린다.
        enable_mock_incidents: 시연용 예시 인시던트를 미리 넣을지 여부
        """
        self.time_window = timedelta(minutes=time_window_minutes)
        self.event_buffer: List[SecurityEvent] = []      # 지금까지 들어온 이벤트 보관함
        self.incidents: Dict[str, Incident] = {}         # 인시던트 ID → 인시던트 객체
        self.store = SQLiteStore()                       # 영속 저장소 (재시작해도 안 날아감)

        # 사용자별 최근 민감 행위 메모리 캐시 (DB 조회 기록 등)
        # user_sensitive_db_touch: "이 사용자가 언제 기밀 DB를 조회했나" 를 기억해둔다.
        #   → 나중에 AI 접속 이벤트가 들어왔을 때 "15분 안이었나?"를 여기서 확인한다.
        # ※ 메모리에만 있으므로 프로그램을 껐다 켜면 사라진다.
        self.user_sensitive_db_touch: Dict[str, datetime] = {}
        self.user_visited_unapproved_ai: Dict[str, Dict[str, Any]] = {}

        # [추가됨] 이미 판정을 끝낸 event_id 모음.
        #   대시보드가 5초마다 폴링하는데 서버는 매번 같은 최신 100건을 돌려주므로,
        #   여기 없는 이벤트만 처리해서 중복 투입을 막는다. (ingest_events 참고)
        self._processed_event_ids: set = set()

        # [추가됨] 인시던트 ID 발급용 접두사별 일련번호.
        #   예전에는 len(self.incidents)+1 로 번호를 만들었는데,
        #   인시던트가 하나라도 지워지면 개수가 줄어 이미 쓴 번호가 다시 나온다.
        #   그래서 개수가 아니라 "지금까지 몇 번까지 발급했는지"를 따로 센다.
        self._incident_seq: Dict[str, int] = {}

        if enable_mock_incidents:
            self._init_mock_incidents()

        # SQLite에서 기존 저장된 인시던트 로드
        # (대시보드를 껐다 켜도 이전에 발생한 인시던트가 그대로 보이게 하기 위함)
        persisted = self.store.get_all_incidents()
        for inc in persisted:
            self.incidents[inc.incident_id] = inc

        # 껐다 켠 뒤에도 번호가 겹치지 않도록, 이미 있는 인시던트의 최대 번호에서 이어 센다.
        self._seed_incident_seq()

    def _seed_incident_seq(self) -> None:
        """
        이미 존재하는 인시던트 ID에서 접두사별 최대 일련번호를 읽어 카운터를 맞춘다.

        예) INC-SEC-003 이 이미 있으면 _incident_seq["INC-SEC"] = 3 으로 두고
            다음 발급은 INC-SEC-004 부터 시작한다.
        """
        for inc_id in self.incidents.keys():
            prefix, _, suffix = inc_id.rpartition("-")     # "INC-SEC-003" → ("INC-SEC", "-", "003")
            if not prefix or not suffix.isdigit():
                continue                                  # 형식이 다른 ID는 건너뛴다
            num = int(suffix)
            if num > self._incident_seq.get(prefix, 0):
                self._incident_seq[prefix] = num

    def _next_incident_id(self, prefix: str) -> str:
        """
        접두사별로 겹치지 않는 인시던트 ID를 발급한다.

        카운터는 한 방향으로만 올라가고, 혹시 메모리나 DB에 같은 번호가 이미 있으면
        그 번호는 건너뛴다. 따라서 인시던트를 지워도 예전 번호가 재사용되지 않는다.
        """
        seq = self._incident_seq.get(prefix, 0)
        while True:
            seq += 1
            inc_id = f"{prefix}-{seq:03d}"
            if inc_id in self.incidents:
                continue                                  # 메모리에 이미 있음 → 다음 번호
            try:
                if self.store.get_incident(inc_id) is not None:
                    continue                              # DB에 이미 있음 → 다음 번호
            except Exception:
                pass                                      # DB 조회 실패해도 발급은 계속한다
            self._incident_seq[prefix] = seq
            return inc_id

    def _init_mock_incidents(self):
        """
        사전 등록된 기준 인시던트 데이터 초기화 (하위 호환성 유지)

        대시보드를 처음 켰을 때 화면이 비어 있으면 곤란하므로
        예시 인시던트 4건을 미리 만들어 넣는다. 전부 가짜 데이터다.

        ⚠ 주의: 이 4건이 실제 탐지 결과와 같은 화면에 섞여서 표시된다.
          시연 때 "이게 진짜 탐지한 건가요?"라는 질문이 나올 수 있으므로
          화면에서 모의 데이터임을 구분 표기하는 것이 좋다.

          INC-001 CRITICAL : 외부 침투 후 고객정보 대량 유출
          INC-002 HIGH     : 섀도우 AI 유출 (NexusGuard 주력 시나리오)
          INC-003 LOW      : 정상 업무 트래픽 (대조군)
          INC-004 MEDIUM   : WATCH 상태 예시
        """
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

        # INC-003 (NORMAL / LOW: 사내 정규 협업 SaaS 정상 트래픽 및 정기 보안 정책 준수)
        inc_3 = Incident(
            incident_id="INC-003",
            title="사내 정규 협업 SaaS(Slack/Zoom) 정상 트래픽 및 보안 정책 준수",
            category=IncidentCategory.INSIDER_DATA_THEFT,
            severity=Severity.LOW,
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

        # INC-004 (WATCH / MEDIUM: 인사팀 단말의 비인가 내부 서브넷 탐색 및 사전 관찰 대상 등록)
        inc_4 = Incident(
            incident_id="INC-004",
            title="인사팀 단말의 비인가 내부 서브넷 탐색 징후 및 사전 관찰 대상(WATCH) 등록",
            category=IncidentCategory.UNAUTHORIZED_PORT,
            severity=Severity.MEDIUM,
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
        """
        이벤트 버퍼에 이벤트 추가 및 상태 기계 상관분석 수행

        여러 이벤트를 한꺼번에 엔진에 밀어 넣는 입구다.
        들어온 이벤트를 하나씩 update_user_risk()에 넘겨 판정시킨다.

        [수정됨] 예전에는 더미 로그만 이 입구로 들어왔으나,
          이제 storage/memory_store.py 에서 Railway 실제 수집 로그도 여기로 넘긴다.

        [수정됨] 같은 event_id 가 두 번 들어오면 두 번째는 건너뛴다.
          Railway 서버의 GET /events 는 매번 최신 100건을 그대로 돌려주고
          대시보드는 5초마다 폴링하므로, 막지 않으면 같은 이벤트가 계속 재투입되어
          상태가 무한히 재전이하고 risk_history 가 분당 수천 건씩 쌓인다.
        """
        # 처음 보는 이벤트만 추려낸다.
        new_events: List[SecurityEvent] = []
        for ev in events:
            if ev.event_id in self._processed_event_ids:
                continue                                  # 이미 처리한 이벤트 → 무시
            self._processed_event_ids.add(ev.event_id)
            new_events.append(ev)

        if not new_events:
            return                                        # 전부 중복이면 할 일이 없다

        self.event_buffer.extend(new_events)
        # 이벤트 timestamp 기준 정렬 (도착 역순 보정)
        # 네트워크 사정으로 나중에 발생한 로그가 먼저 도착할 수 있으므로
        # 실제 발생 시각 순으로 다시 줄을 세운다. 시간 순서가 틀리면 상관분석이 어긋난다.
        self.event_buffer.sort(key=lambda e: e.timestamp)

        # [수정됨] 예전에는 정렬되지 않은 원본 events 를 그대로 순회했다.
        #   버퍼만 정렬하고 판정은 도착 순서대로 하면
        #   "DB 조회 → AI 접속" 순서가 뒤집혀 WATCH 승격을 놓친다.
        #   그래서 판정도 timestamp 오름차순으로 돌린다.
        for ev in sorted(new_events, key=lambda e: e.timestamp):
            self.update_user_risk(ev)

    def update_user_risk(self, event: SecurityEvent) -> None:
        """
        단일 이벤트에 대한 2단계 위험 상태 기계(State Machine) 전이 처리
        1. 전송 전 조건(민감 DB 조회 + 미승인 AI 질의) -> WATCH 승격 & 1차 알림
        2. WATCH 상태에서 외부 전송 발생 -> HIGH Incident 확정 & 2차 알림

        ★ 이 함수가 엔진의 판정 로직 전부다. 이벤트 1건이 들어올 때마다 실행된다.

        [처리 순서]
          0) 이 사용자의 현재 상태를 DB에서 확인 (NORMAL인지 WATCH인지)
          1) 이벤트가 '기밀 DB 조회'인가?      → 시각만 기억해두고 종료 (조건 A 성립)
          2) 이벤트가 '외부 전송'인가?          → 현재 상태에 따라 분기
               2-1) 지금 WATCH다              → HIGH 확정 (유출 킬체인 완성)
               2-2) 지금 NORMAL인데 과거 WATCH 이력 있다 → HIGH 직행 (잠복형 유출)
               2-3) 미승인 AI로 파일 첨부      → WATCH 승격
               2-4) 그냥 대용량 전송           → WATCH 승격
          3) 이벤트가 '미승인 AI 접속'인가?     → 15분 내 DB 조회가 있었으면 WATCH 승격 (조건 A+B)

        주의: 각 분기 끝에 return이 있다. 한 이벤트는 한 가지 판정만 받는다.
        """
        # 사용자를 무엇으로 식별할지 정한다. 계정명이 있으면 계정명, 없으면 IP를 쓴다.
        user = event.actor.user_id or event.actor.src_ip
        now_utc = datetime.utcnow()

        # 1. 만료 시각(expires_at > now) 기준 현재 유효 상태 조회
        #    TTL이 지난 상태는 조회되지 않으므로, 결과가 없으면 NORMAL로 본다.
        #    ★ 여기서 '30분 지나면 자동으로 NORMAL로 돌아간다'는 자가 치유가 구현된다.
        current_risk = self.store.get_active_risk(user)
        old_state = current_risk["state"] if current_risk else "NORMAL"

        # 2. 행위 특징 분석 (DB, DNS/Web, Firewall)
        # 2.1 DB 조회 행위 포착  ─── WATCH 승격 조건 A
        #     기밀 테이블을 조회했다면, 그 '시각'만 메모리에 적어두고 여기서 끝낸다.
        #     조회 자체는 정상 업무일 수 있으므로 아직 상태를 올리지 않는다.
        #     나중에 AI 접속 이벤트가 들어왔을 때 이 기록과 짝을 맞춘다(2.3 참고).
        if event.log_source == LogSource.DB and event.action == EventAction.SELECT:
            tbl = event.payload.table_name or ""
            query = event.payload.query_string or ""
            # 테이블명이 기밀 목록에 있거나, 쿼리문에 민감 키워드가 섞여 있으면 기밀 조회로 본다
            if tbl in SENSITIVE_TABLES or any(k in query.lower() for k in ["customer", "secret", "vault", "plan"]):
                self.user_sensitive_db_touch[user] = event.timestamp
                return

        # 2.1-b 미승인 AI 사이트 대량 텍스트 붙여넣기(PASTE_ATTEMPT) 판정  [추가됨]
        #
        # ★ 이 검사는 반드시 아래 2.2 파일업로드 판정보다 '앞에' 있어야 한다.
        #   2.2 의 is_file_upload 조건에 log_source == CHROME_EXTENSION 이 들어 있어서,
        #   순서가 뒤바뀌면 붙여넣기가 파일첨부로 오인되어 잘못된 근거가 붙는다.
        #
        # 판정 규칙:
        #   · 이미 WATCH 인 사용자 → HIGH 로 승격. 전송이 실제 일어난 것으로 본다.
        #   · NORMAL 인 사용자     → 상태를 바꾸지 않고 기록만 남긴다.
        #     정상 사용자도 긴 문서를 붙여넣는 일이 흔해서, 이것만으로 올리면 오탐이 된다.
        #     (NexusGuard의 '조건을 모두 만족했을 때만 올린다' 원칙과 같은 맥락이다)
        #
        # 붙여넣은 내용 자체는 수집하지도 저장하지도 않는다. 길이와 패턴 개수만 쓴다.
        if event.action == EventAction.PASTE_ATTEMPT:
            self._handle_paste_attempt(user, old_state, event)
            return

        # 2.2 파일 업로드 시도 또는 외부 데이터 전송 발생 포착 (Chrome Extension / Firewall ALLOW / Web POST)
        target_domain = event.target.domain or ""

        # 이 도메인이 미승인 AI 또는 파일공유 서비스인가?
        # 등록된 목록에 있거나, 도메인 이름에 ai/gpt/claude 같은 단어가 들어 있으면 그렇다고 본다.
        # 새 AI 사이트가 매일 생기므로 목록만으로는 부족해서 이름 검사도 함께 한다.
        is_ai_or_cloud = target_domain in KNOWN_AI_DOMAINS or any(k in target_domain.lower() for k in ["ai", "gpt", "claude", "gemini", "transfer", "dropbox", "box", "drive"])

        file_name = event.payload.file_name or ""
        file_size = event.payload.file_size or event.payload.bytes_sent or 0
        bytes_out = event.payload.bytes_sent or file_size or 0

        # '파일을 첨부하려 했는가' 판정
        # 크롬 확장에서 온 로그이거나 파일명이 있으면 파일 첨부로 본다.
        is_file_upload = (
            event.action == EventAction.FILE_UPLOAD_ATTEMPT or
            event.log_source == LogSource.CHROME_EXTENSION or
            bool(file_name)
        )

        # '외부로 데이터가 나갔는가' 판정 (exfiltration = 유출)
        # 파일 첨부이거나, 방화벽/웹 로그에서 50KB를 넘는 전송이 잡히면 유출로 본다.
        # 50KB 기준을 둔 이유: 일반적인 텍스트 질문은 아무리 길어도 수십 KB를 넘지 않는다.
        #                    그보다 크면 파일을 올린 것으로 볼 수 있다.
        is_exfil = (
            is_file_upload or
            (event.log_source == LogSource.FIREWALL and event.action == EventAction.ALLOW and bytes_out > 50000) or
            (event.log_source == LogSource.WEB and event.action == EventAction.HTTP_POST and bytes_out > 50000)
        )

        if is_exfil:
            # ─────────────────────────────────────────────────────────
            # 전송이 일어났다. 이제 이 사용자의 현재 상태에 따라 처리가 갈린다.
            # ─────────────────────────────────────────────────────────

            # 1) 사용자가 현재 WATCH 상태인 경우 -> 🌟 [2단계] HIGH Incident 확정!
            #    이미 감시 중이던 사람이 실제로 데이터를 내보냈다.
            #    유출 킬체인(기밀 조회 → AI 접속 → 전송)이 완성된 것이므로 바로 확정한다.
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
                #
                #    ★ 여기가 "30분 기다렸다가 유출하면 안 걸리지 않나?"에 대한 답이다.
                #    지금 상태는 NORMAL이지만, 과거에 WATCH였던 적이 있는지 감사 이력을 뒤진다.
                #    이력이 있다면 TTL 만료를 노린 우회 시도로 보고 곧바로 HIGH로 올린다.
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
                    # (기밀 DB 조회 이력은 없지만, 미승인 AI에 파일을 올리는 것 자체가 위험 신호)
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
                    # 아무 정황 없이 갑자기 1MB 넘게 외부로 나가면 그 자체로 이상 징후로 본다.
                    # ※ 1MB라는 기준은 코드에 고정되어 있다. 팀에서 확정한 임계치는 아니다.
                    new_state = "WATCH"
                    score = 72
                    reasons = [
                        f"비인가 외부 서비스로의 단독 비정상 대용량 전송 포착 ({bytes_out / (1024*1024):.2f} MB)",
                        "임계치(1MB) 초과 Outbound Traffic Spike 단독 이상 징후 감지"
                    ]
                    self._apply_state_transition(user, old_state, new_state, score, reasons, event)
                    return

        # 2.3 미승인 AI / 외부 SaaS 단순 접근 및 질의 포착 (전송 이전 선제 감시)
        # ★ NexusGuard의 핵심 차별점이 구현된 부분이다.
        #   데이터가 나가기 '전에' 감시를 시작하는 곳.
        if (event.log_source in [LogSource.DNS, LogSource.WEB, LogSource.WINDOWS_AGENT]) and is_ai_or_cloud:
            # 이 사용자가 어느 AI 사이트에 언제 접속했는지 기록해둔다
            self.user_visited_unapproved_ai[user] = {
                "domain": target_domain,
                "time": event.timestamp
            }

            # 민감 DB 조회가 선행되었는지 확인 (self.time_window 이내)
            # 여기가 '조건 A + 조건 B를 모두 만족했는가'를 검사하는 지점이다.
            # 단순히 AI 사이트에 접속한 것만으로는 WATCH로 올리지 않는다.
            # 반드시 그 직전에 기밀 DB 조회가 있었어야 한다.
            #
            # [수정됨] 예전에는 여기에 timedelta(minutes=15) 가 박혀 있었다.
            #   __init__ 에서 만든 self.time_window 는 아무 데서도 쓰이지 않아서,
            #   CorrelationEngine(time_window_minutes=30) 처럼 인자를 바꿔도 효과가 없었다.
            #   이제 self.time_window 하나로 통일했다.
            db_touch_time = self.user_sensitive_db_touch.get(user)
            if db_touch_time and (event.timestamp - db_touch_time) <= self.time_window:
                # 🌟 [1단계] WATCH 상태 전이 (전송 이전 선제 감시)
                #    아직 단 1바이트도 나가지 않았지만 감시를 시작한다.
                new_state = "WATCH"
                score = 68
                window_min = int(self.time_window.total_seconds() // 60)
                reasons = [
                    f"사내 기밀 DB({event.actor.user_id or '단말'}) SELECT 조회 선행",
                    f"{window_min}분 내 미승인 외부 서비스({target_domain}) 접근 포착",
                    "데이터 외부 반출 위험으로 사전 감시 승격"
                ]
                self._apply_state_transition(user, old_state, new_state, score, reasons, event)
                return

    # ------------------------------------------------------------------
    # 붙여넣기(PASTE_ATTEMPT) 판정  [추가됨]
    # ------------------------------------------------------------------

    # 패턴 키를 사람이 읽을 수 있는 이름으로 바꾸는 표.
    # 관리자가 근거를 볼 때 "rrn 3" 보다 "주민등록번호 형태 3건"이 이해가 빠르다.
    PASTE_PATTERN_LABELS = {
        "rrn": "주민등록번호 형태",
        "card": "카드번호 형태",
        "email": "이메일",
        "phone": "전화번호",
    }

    @staticmethod
    def _format_pattern_hits(pattern_hits: Dict[str, Any]) -> str:
        """
        패턴 검출 개수를 사람이 읽을 문장으로 만든다.

        예) {"rrn": 3, "card": 1, "email": 0} → "주민등록번호 형태 3건, 카드번호 형태 1건"
        0건인 항목은 빼고, 전부 0이면 "없음"을 돌려준다.

        ※ 여기서 다루는 것은 개수뿐이다. 붙여넣은 문자열은 애초에 이 함수까지 오지 않는다.
        """
        parts = []
        for key, label in CorrelationEngine.PASTE_PATTERN_LABELS.items():
            try:
                count = int(pattern_hits.get(key, 0) or 0)
            except (ValueError, TypeError):
                count = 0            # 값이 깨져 있으면 0으로 취급하고 넘어간다
            if count > 0:
                parts.append(f"{label} {count}건")
        return ", ".join(parts) if parts else "없음"

    def _handle_paste_attempt(self, user: str, old_state: str, event: SecurityEvent) -> None:
        """
        붙여넣기 이벤트 하나를 판정한다.

        WATCH → HIGH 로 올리거나, 그 외 상태에서는 기록만 남기고 끝낸다.
        인시던트는 만들지 않는다. (상태 전이와 근거만 남기도록 범위를 잡았다)
        """
        extra = event.payload.extra or {}

        # 문자 수. 값이 없거나 깨져 있어도 판정이 멈추지 않도록 0으로 처리한다.
        try:
            text_length = int(extra.get("text_length", 0) or 0)
        except (ValueError, TypeError):
            text_length = 0

        pattern_hits = extra.get("pattern_hits") or {}
        if not isinstance(pattern_hits, dict):
            pattern_hits = {}

        target_domain = event.target.domain or "unknown"
        hits_str = self._format_pattern_hits(pattern_hits)

        # 두 경우 모두에 들어가는 공통 근거.
        # 마지막 줄은 감사나 발표에서 "내용을 봤느냐"는 질문에 답하기 위해 일부러 남긴다.
        base_reasons = [
            f"미승인 생성형 AI({target_domain})에 대량 텍스트 붙여넣기 감지 (Chrome Extension)",
            f"붙여넣은 문자 수: {text_length:,}자",
            f"민감정보 패턴 검출: {hits_str}",
            "붙여넣은 내용 자체는 수집·저장하지 않음 (길이와 패턴 검출 개수만 기록)",
        ]

        if old_state == "WATCH":
            # 🌟 [2단계] 이미 감시 중이던 사용자가 붙여넣었다.
            #    기밀 DB를 보고 → AI 사이트에 들어가 → 실제로 텍스트를 넣은 것이므로
            #    파일 업로드와 동일하게 '전송이 일어났다'고 판단한다.
            reasons = ["사전 감시(WATCH) 등록 사용자의 붙여넣기 전송 확인"] + base_reasons
            self._apply_state_transition(user, old_state, "HIGH", 93, reasons, event)
            return

        # NORMAL(또는 이미 HIGH 이상) 상태 → 상태는 그대로 두고 기록만 남긴다.
        # from_state 와 to_state 를 같게 넣어 "전이 없이 관찰만 했다"는 뜻을 남긴다.
        # 이 기록은 나중에 이 사용자가 WATCH가 됐을 때 정황 자료로 쓸 수 있다.
        self.store.append_history(
            user, old_state, old_state,
            "[기록] " + " / ".join(base_reasons)
        )

    def _apply_state_transition(self, user: str, old_state: str, new_state: str,
                                score: int, reasons: List[str], event: SecurityEvent, incident=None):
        """
        판정 결과를 실제로 반영하는 함수. 위 update_user_risk()의 모든 분기가 결국 여기로 모인다.

        하는 일 3가지:
          1) user_risk 테이블에 현재 상태 저장 (만료 시각 포함)
          2) risk_history 테이블에 전이 기록 남기기 (감사 이력, 지우지 않음)
          3) 알림 훅 호출 (respond.py)
        """
        now_utc = datetime.utcnow()
        # 새 상태에 맞는 TTL을 지금 시각에 더해 만료 시각을 계산한다.
        # TTL 표에 없는 상태가 들어오면 안전하게 1시간을 준다.
        expires_at = now_utc + TTL.get(new_state, timedelta(hours=1))

        # 중복 알림 억제: 상태가 동일하면 만료 시간만 연장
        # 이미 WATCH인 사람에게 또 WATCH 조건이 걸렸다고 알림을 다시 보내면
        # 관제사가 같은 내용을 반복해서 받게 된다. 그래서 감시 시간만 늘리고 조용히 끝낸다.
        if new_state == old_state:
            self.store.extend_expiry(user, expires_at)
            return

        # 상태 갱신 및 이력 적재
        self.store.upsert_risk(user, new_state, score, reasons, expires_at)     # 현재 상태 덮어쓰기
        self.store.append_history(user, old_state, new_state, " / ".join(reasons))  # 이력은 계속 쌓기

        # SOAR 알림 훅 호출
        # 여기서 2단계 알림이 갈린다. WATCH면 1차 주의 알림, HIGH면 2차 긴급 알림.
        # (실제 발송 로직은 engine/respond.py 에 있다)
        on_risk_state_changed(user, old_state, new_state, reasons, incident)

    def _create_dynamic_incident(self, user: str, event: SecurityEvent, bytes_out: int,
                                 file_name: Optional[str] = None, file_size: Optional[int] = None,
                                 title_prefix: str = "", evidence_note: Optional[str] = None) -> Incident:
        """
        HIGH 확정 시 침해사고(Incident) 객체를 만들어 저장한다.

        '동적(dynamic)'이라 부르는 이유: _init_mock_incidents()의 고정 예시와 달리
        실제 이벤트가 들어왔을 때 그 내용으로 즉석에서 만들어지기 때문이다.

        파일명이 있느냐 없느냐에 따라 두 갈래로 나뉜다.
          - 파일명 있음: 크롬 확장이 첨부를 잡은 경우 → 증거가 구체적이라 95점
          - 파일명 없음: 방화벽/웹 로그에서 대용량 전송만 잡힌 경우 → 92점

        만들어 넣는 내용:
          title / summary  : 사람이 읽을 제목과 요약
          evidences        : 왜 위험하다고 판단했는지 근거 (배점 포함)
          network_hops     : 킬체인 시각화용 경로
          soar_actions     : 관리자가 고를 수 있는 대응 조치 목록 (자동 실행 아님)
        """
        # 인시던트 번호 부여: INC-SEC-001, INC-SEC-002 ... 형태
        # ※ 현재 개수 + 1 방식이라 삭제가 일어나면 번호가 겹칠 수 있다.
        inc_id = self._next_incident_id("INC-SEC")   # [수정됨] 개수 기반 번호 → 겹치지 않는 일련번호
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
        """
        1단계 선제 감시(WATCH) 인시던트 생성 및 등록

        WATCH도 화면에 한 건으로 보여주기 위해 인시던트 객체를 만든다.
        severity는 MEDIUM(노랑)이고 점수는 68점 — 아직 유출이 아니므로 HIGH가 아니다.

        ※ 대시보드의 시뮬레이션 버튼에서 호출된다.
          sc(scenario) 인자로 시연용 시나리오 정보를 받는다.
        """
        inc_id = self._next_incident_id("INC-WATCH")   # [수정됨] 개수 기반 번호 → 겹치지 않는 일련번호
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
        """
        3단계 오탐 자가 치유(NORMAL) 인시던트 생성 및 등록

        WATCH였던 사람이 30분간 아무 전송도 하지 않아 정상으로 되돌아갔을 때,
        "이런 일이 있었고 문제없이 종료됐다"는 기록을 한 건 남긴다.
        status가 RESOLVED이고 점수는 20점이다.

        ※ 이 함수도 시뮬레이션 버튼에서 호출된다.
          실제 TTL 만료를 감지해 자동으로 불러주는 주기 작업은 아직 없다.
        """
        inc_id = self._next_incident_id("INC-NORM")   # [수정됨] 개수 기반 번호 → 겹치지 않는 일련번호
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

    # ========================================================================
    # 대시보드에서 데이터를 꺼내갈 때 쓰는 조회 함수들
    # ========================================================================

    def get_all_incidents(self) -> List[Incident]:
        """모든 인시던트를 최신순으로 돌려준다. 대시보드 목록 화면에 쓰인다."""
        return sorted(list(self.incidents.values()), key=lambda x: x.created_at, reverse=True)

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        """인시던트 한 건을 ID로 찾아 돌려준다. 목록에서 클릭했을 때 상세 화면용."""
        return self.incidents.get(incident_id)

    def get_watch_users(self) -> List[Dict[str, Any]]:
        """
        현재 WATCH 상태에 있는 감시 대상자 목록 반환

        TTL이 지난 사람은 SQLite 조회 단계에서 이미 걸러지므로
        여기서 나오는 것은 '지금 유효하게 감시 중인' 사람들뿐이다.
        """
        return self.store.get_all_active_risks()

