"""
NexusGuard - Dummy Log Generator
시나리오 A(외부 침투 및 내부 피보팅) & 시나리오 B(섀도우 AI 데이터 유출) 모의 원천 로그 생성기

=====================================================================
[이 파일이 하는 일]
=====================================================================
가짜 보안 로그를 만들어내는 파일이다. 실제 로그가 아니다.

왜 필요한가:
  · 대시보드를 처음 켰을 때 화면이 텅 비어 있으면 아무것도 확인할 수 없다
  · 실제 침투나 유출을 재현해볼 수는 없으므로 시연용 데이터가 필요하다
  · 엔진이 제대로 판정하는지 검증하는 용도로도 쓴다

[만드는 로그 3종]
  시나리오 A : 외부 공격자가 침투해 내부로 파고들어 고객정보를 빼가는 흐름
               브루트포스 → 로그인 성공 → SSH 이동 → DB 조회 → 외부 유출
  시나리오 B : 내부 직원이 기밀 조회 후 ChatGPT에 올리는 흐름
               ★ NexusGuard 주력 시나리오. WATCH → HIGH 전이를 검증한다
  배경 로그  : 평상시 정상 트래픽. 위험 로그만 있으면 비현실적이므로 섞어준다

[⚠ 중요]
현재 엔진(correlation.py)에 실제로 투입되는 이벤트는
storage/memory_store.py 를 통해 들어오는 이 파일의 더미 로그뿐이다.
Railway에서 받아온 진짜 로그는 엔진까지 도달하지 않는다.

즉 대시보드에 보이는 인시던트와 위험 상태는 대부분 여기서 만든 가짜 데이터다.
시연할 때 이 점을 구분해서 설명해야 한다.
"""

from datetime import datetime, timedelta
from typing import List
from nexusguard.schemas.event import (
    SecurityEvent, LogSource, EventAction, Actor, Target, PayloadMetadata
)


def generate_scenario_a_logs(base_time: datetime = None) -> List[SecurityEvent]:
    """
    시나리오 A: 외부 침투 킬체인 및 내부 측면이동(Lateral Movement) 로그 시뮬레이션
    - 외부 브루트포스 5회 실패 -> 로그인 성공 -> 내부 SSH 접속 -> DB 접속 -> 기밀 조회 -> 외부 C2 유출

    [용어]
      브루트포스(Brute Force) : 비밀번호를 무작정 계속 넣어보며 뚫는 공격
      측면이동(Lateral Movement) : 한 서버를 뚫은 뒤 그것을 발판 삼아
                                   내부의 다른 서버로 옮겨 다니는 것
      C2 (Command & Control)  : 공격자가 훔친 데이터를 보내는 외부 서버

    base_time을 인자로 받는 이유:
      이벤트마다 시각을 조금씩 어긋나게 만들어야 '순서대로 일어난 일'처럼 보인다.
      기준 시각을 하나 정하고 거기에 몇 초씩 더해가는 방식이다.
    """
    if base_time is None:
        base_time = datetime.now() - timedelta(minutes=15)

    events: List[SecurityEvent] = []
    attacker_ip = "203.116.45.23"
    web_ip = "10.0.0.10"
    internal_ip = "10.0.0.20"
    db_ip = "10.0.0.30"
    target_user = "admin"

    # 1. 외부 무차별 대입 공격 (인증 실패 5회)
    for i in range(5):
        t = base_time + timedelta(seconds=i * 12)
        events.append(
            SecurityEvent(
                event_id=f"EVT-A-{100+i}",
                timestamp=t,
                log_source=LogSource.AUTH,
                actor=Actor(user_id=target_user, src_ip=attacker_ip, src_port=49152 + i),
                target=Target(dst_ip=web_ip, dst_port=443, hostname="web-prod-01"),
                action=EventAction.LOGIN_FAILURE,
                payload=PayloadMetadata(category="BruteForce", extra={"attempt": i + 1}),
                raw_message=f"{t.strftime('%b %d %H:%M:%S')} web-prod-01 sshd: Failed password for {target_user} from {attacker_ip} port {49152+i}"
            )
        )

    # 2. 관리자 계정 로그인 성공
    t_succ = base_time + timedelta(seconds=75)
    events.append(
        SecurityEvent(
            event_id="EVT-A-105",
            timestamp=t_succ,
            log_source=LogSource.AUTH,
            actor=Actor(user_id=target_user, src_ip=attacker_ip, src_port=49160),
            target=Target(dst_ip=web_ip, dst_port=443, hostname="web-prod-01"),
            action=EventAction.LOGIN_SUCCESS,
            payload=PayloadMetadata(category="Authentication"),
            raw_message=f"{t_succ.strftime('%b %d %H:%M:%S')} web-prod-01 sshd: Accepted password for {target_user} from {attacker_ip} port 49160"
        )
    )

    # 3. 방화벽: 외부 -> 웹서버 허용
    t_fw1 = base_time + timedelta(seconds=76)
    events.append(
        SecurityEvent(
            event_id="EVT-A-106",
            timestamp=t_fw1,
            log_source=LogSource.FIREWALL,
            actor=Actor(user_id=target_user, src_ip=attacker_ip, src_port=49160),
            target=Target(dst_ip=web_ip, dst_port=443),
            action=EventAction.ALLOW,
            payload=PayloadMetadata(bytes_sent=4500),
            raw_message=f"{t_fw1.strftime('%b %d %H:%M:%S')} fw: ALLOW TCP {attacker_ip}:49160 -> {web_ip}:443"
        )
    )

    # 4. 피보팅(Lateral Movement): 웹서버 -> 내부 서버 SSH(22) 접속
    t_ssh = base_time + timedelta(seconds=130)
    events.append(
        SecurityEvent(
            event_id="EVT-A-107",
            timestamp=t_ssh,
            log_source=LogSource.FIREWALL,
            actor=Actor(user_id=target_user, src_ip=web_ip, src_port=53120),
            target=Target(dst_ip=internal_ip, dst_port=22, hostname="internal-core-01"),
            action=EventAction.ALLOW,
            payload=PayloadMetadata(category="LateralMovement"),
            raw_message=f"{t_ssh.strftime('%b %d %H:%M:%S')} fw: ALLOW TCP {web_ip}:53120 -> {internal_ip}:22"
        )
    )

    # 5. 내부 서버 -> DB 서버(3306) 접속
    t_db_conn = base_time + timedelta(seconds=210)
    events.append(
        SecurityEvent(
            event_id="EVT-A-108",
            timestamp=t_db_conn,
            log_source=LogSource.FIREWALL,
            actor=Actor(user_id=target_user, src_ip=internal_ip, src_port=44120),
            target=Target(dst_ip=db_ip, dst_port=3306, hostname="db-cust-01"),
            action=EventAction.ALLOW,
            payload=PayloadMetadata(category="DatabaseAccess"),
            raw_message=f"{t_db_conn.strftime('%b %d %H:%M:%S')} fw: ALLOW TCP {internal_ip}:44120 -> {db_ip}:3306"
        )
    )

    # 6. DB 감사 로그: 고객 기밀 테이블 대량 조회
    t_db_query = base_time + timedelta(seconds=230)
    events.append(
        SecurityEvent(
            event_id="EVT-A-109",
            timestamp=t_db_query,
            log_source=LogSource.DB,
            actor=Actor(user_id=target_user, src_ip=internal_ip, src_port=44120),
            target=Target(dst_ip=db_ip, dst_port=3306, hostname="db-cust-01"),
            action=EventAction.SELECT,
            payload=PayloadMetadata(
                query_string="SELECT user_id, rrn, credit_card_num, balance FROM customer_vault",
                table_name="customer_vault",
                rows_affected=24500,
                category="PrivilegedDataAccess"
            ),
            raw_message=f"{t_db_query.strftime('%b %d %H:%M:%S')} mysql-audit: user={target_user} ip={internal_ip} query='SELECT * FROM customer_vault' rows=24500"
        )
    )

    # 7. 외부 C2 서버로 대용량 비정상 데이터 유출
    t_exfil = base_time + timedelta(seconds=310)
    events.append(
        SecurityEvent(
            event_id="EVT-A-110",
            timestamp=t_exfil,
            log_source=LogSource.FIREWALL,
            actor=Actor(src_ip=internal_ip, src_port=58911),
            target=Target(dst_ip=attacker_ip, dst_port=10443),
            action=EventAction.ALLOW,
            payload=PayloadMetadata(bytes_sent=158000000, category="Exfiltration"),
            raw_message=f"{t_exfil.strftime('%b %d %H:%M:%S')} fw: ALLOW TCP {internal_ip}:58911 -> {attacker_ip}:10443 bytes=158000000"
        )
    )

    return events


def generate_scenario_b_logs(base_time: datetime = None) -> List[SecurityEvent]:
    """
    시나리오 B: 내부 직원의 섀도우 AI 접속 및 기밀 데이터 유출 시뮬레이션
    - 내부 PC(192.168.10.45) DB 조회 -> 3분 내 chatgpt.com DNS 질의 -> 외부 AI 업로드 트래픽

    ★ NexusGuard가 풀려는 문제를 그대로 재현한 시나리오다.

    이 세 이벤트가 엔진에 순서대로 들어가면 다음이 일어난다.
      1) DB 조회       → 엔진이 조회 시각만 기억 (아직 상태 안 바뀜)
      2) ChatGPT 접속  → 15분 안이므로 조건 A+B 성립 → WATCH 승격 (68점)
      3) 업로드 트래픽 → WATCH 상태에서 전송 발생   → HIGH 확정 (92점)

    엔진이 제대로 동작하는지 확인하려면 이 시나리오 결과를 보면 된다.
    """
    if base_time is None:
        base_time = datetime.now() - timedelta(minutes=8)

    events: List[SecurityEvent] = []
    employee_ip = "192.168.10.45"
    employee_user = "kim_marketing"
    db_ip = "10.0.0.30"

    # 1. 마케팅팀 직원이 DB에서 재무/기획 데이터 조회
    t_db = base_time
    events.append(
        SecurityEvent(
            event_id="EVT-B-201",
            timestamp=t_db,
            log_source=LogSource.DB,
            actor=Actor(user_id=employee_user, src_ip=employee_ip, src_port=51200),
            target=Target(dst_ip=db_ip, dst_port=3306, hostname="db-cust-01"),
            action=EventAction.SELECT,
            payload=PayloadMetadata(
                query_string="SELECT campaign_strategy, q3_budget_plan FROM corp_strategic_plan",
                table_name="corp_strategic_plan",
                rows_affected=150,
                category="ConfidentialDocAccess"
            ),
            raw_message=f"{t_db.strftime('%b %d %H:%M:%S')} mysql-audit: user={employee_user} ip={employee_ip} table=corp_strategic_plan rows=150"
        )
    )

    # 2. 직후 동일 PC에서 생성형 AI(chatgpt.com) DNS 질의
    t_dns = base_time + timedelta(seconds=110)
    events.append(
        SecurityEvent(
            event_id="EVT-B-202",
            timestamp=t_dns,
            log_source=LogSource.DNS,
            actor=Actor(user_id=employee_user, src_ip=employee_ip),
            target=Target(domain="chatgpt.com"),
            action=EventAction.QUERY,
            payload=PayloadMetadata(category="Generative_AI"),
            raw_message=f"{t_dns.strftime('%H:%M:%S')} {employee_ip} chatgpt.com A"
        )
    )

    # 3. 브라우저를 통한 외부 AI API 데이터 업로드
    t_post = base_time + timedelta(seconds=145)
    events.append(
        SecurityEvent(
            event_id="EVT-B-203",
            timestamp=t_post,
            log_source=LogSource.FIREWALL,
            actor=Actor(user_id=employee_user, src_ip=employee_ip, src_port=56110),
            target=Target(domain="api.openai.com", dst_port=443),
            action=EventAction.ALLOW,
            payload=PayloadMetadata(bytes_sent=1450000, category="AI_Data_Upload"),
            raw_message=f"{t_post.strftime('%b %d %H:%M:%S')} proxy: ALLOW POST https://api.openai.com/v1/chat bytes=1450000 from {employee_ip}"
        )
    )

    return events


def generate_background_dns_logs(base_time: datetime = None) -> List[SecurityEvent]:
    """
    정상 및 일상적인 사내 섀도우 IT/SaaS DNS 질의 로그

    평범한 직원들이 슬랙, 노션, 깃허브에 접속하는 일상 트래픽이다.

    왜 필요한가:
      · 위험한 로그만 있으면 화면이 온통 빨간색이라 현실감이 없다
      · 거버넌스 화면에 보여줄 '외부 서비스 자산 목록'이 이 로그에서 만들어진다
      · 정상 트래픽 속에서 위험을 골라내는 것이 관제의 본질이므로 대조군이 필요하다

    log_source가 DNS인 유일한 곳이기도 하다.
    (memory_store.py 가 DNS만 거버넌스로 넘기므로, 거버넌스 자산은 사실상 여기서만 채워진다)
    """
    if base_time is None:
        base_time = datetime.now() - timedelta(minutes=25)

    # (출발지 IP, 도메인, 기준시각으로부터 몇 초 뒤, 서비스 분류)
    samples = [
        ("192.168.10.45", "slack.com", 0, "Approved_SaaS"),
        ("192.168.10.88", "dropbox.com", 250, "File_Sharing"),
        ("192.168.10.12", "notion.so", 480, "Productivity"),
        ("192.168.10.88", "wetransfer.com", 720, "File_Sharing"),
        ("192.168.10.60", "claude.ai", 950, "Generative_AI"),
        ("192.168.10.104", "github.com", 1200, "Development"),
    ]

    events: List[SecurityEvent] = []
    for idx, (ip, domain, sec_offset, cat) in enumerate(samples):
        t = base_time + timedelta(seconds=sec_offset)
        events.append(
            SecurityEvent(
                event_id=f"EVT-BG-{300+idx}",
                timestamp=t,
                log_source=LogSource.DNS,
                actor=Actor(src_ip=ip),
                target=Target(domain=domain),
                action=EventAction.QUERY,
                payload=PayloadMetadata(category=cat),
                raw_message=f"{t.strftime('%H:%M:%S')} {ip} {domain} A"
            )
        )
    return events


def get_all_initial_events() -> List[SecurityEvent]:
    """
    초기 데모에 필요한 모든 이벤트 통합 반환 (시간순 정렬)

    이 파일의 출구. storage/memory_store.py 가 프로그램 시작 시 이 함수를 부른다.

    시각을 서로 다르게 준 이유:
      배경 로그(20분 전) → 시나리오 A(12분 전) → 시나리오 B(6분 전)
      이렇게 배치하면 "평소에 잘 지내다가 사고가 났다"는 시간 흐름이 만들어진다.

    마지막에 시간순으로 다시 정렬하는 이유:
      엔진은 이벤트를 들어온 순서대로 처리한다.
      순서가 뒤섞이면 "AI 접속이 DB 조회보다 먼저" 처리되어
      WATCH 승격 조건이 성립하지 않는다.
    """
    now = datetime.now()
    all_events = []
    all_events.extend(generate_scenario_a_logs(now - timedelta(minutes=12)))
    all_events.extend(generate_scenario_b_logs(now - timedelta(minutes=6)))
    all_events.extend(generate_background_dns_logs(now - timedelta(minutes=20)))
    all_events.sort(key=lambda e: e.timestamp)   # 시간 순서 보정 (중요)
    return all_events
