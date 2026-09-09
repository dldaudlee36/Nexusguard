"""
NexusGuard - Dummy Log Generator
시나리오 A(외부 침투 및 내부 피보팅) & 시나리오 B(섀도우 AI 데이터 유출) 모의 원천 로그 생성기
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
    """
    if base_time is None:
        base_time = datetime.now() - timedelta(minutes=8)

    events: List[SecurityEvent] = []
    employee_ip = "192.168.10.45"
    employee_user = "user_corp"
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
    """
    if base_time is None:
        base_time = datetime.now() - timedelta(minutes=25)

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
    """초기 데모에 필요한 모든 이벤트 통합 반환 (시간순 정렬)"""
    now = datetime.now()
    all_events = []
    all_events.extend(generate_scenario_a_logs(now - timedelta(minutes=12)))
    all_events.extend(generate_scenario_b_logs(now - timedelta(minutes=6)))
    all_events.extend(generate_background_dns_logs(now - timedelta(minutes=20)))
    all_events.sort(key=lambda e: e.timestamp)
    return all_events
