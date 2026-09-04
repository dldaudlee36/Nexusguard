"""
NexusGuard - Multi-Dimensional Correlation Engine
다차원 보안 이벤트 상관분석 및 인시던트 자동 생성 엔진
"""

from typing import List, Dict, Optional
from datetime import datetime, timedelta
from nexusguard.schemas.event import SecurityEvent, LogSource, EventAction
from nexusguard.schemas.incident import (
    Incident, Severity, IncidentCategory, IncidentStatus, NetworkHop
)


class CorrelationEngine:
    """이기종 보안 이벤트 상관분석 코어 엔진"""

    def __init__(self, time_window_minutes: int = 15):
        self.time_window = timedelta(minutes=time_window_minutes)
        self.event_buffer: List[SecurityEvent] = []
        self.incidents: Dict[str, Incident] = {}
        self._init_mock_incidents()

    def _init_mock_incidents(self):
        """실제 기업 보안 사고 사례를 반영한 10대 핵심 인시던트 데이터 초기화"""
        
        # 1. INC-001 (CRITICAL: 금융 고객 개인정보 2.4만 건 대량 탈취 및 C2 유출)
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
            created_at=datetime.now() - timedelta(minutes=7),
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

        # 2. INC-002 (HIGH: 마케팅팀 미승인 생성형 AI를 통한 전략기획서 유출 의심)
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
            created_at=datetime.now() - timedelta(minutes=4),
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

        # 3. INC-003 (CRITICAL: 제조 공정망(OT) 랜섬웨어 선행 단계 비인가 RDP 접속 및 복원지점 삭제)
        inc_3 = Incident(
            incident_id="INC-003",
            title="제조 공정망(OT) 랜섬웨어 선행 단계 비인가 RDP 접속 및 볼륨 섀도우 삭제",
            category=IncidentCategory.RANSOMWARE_PRECURSOR,
            severity=Severity.CRITICAL,
            score=98,
            status=IncidentStatus.ACTIVE,
            summary="새벽 3시 비인가 RDP(:3389) 세션 생성 후 vssadmin 볼륨 섀도우 복원 지점 삭제 명령어 실행 감지",
            actor="172.16.50.88 (ot_operator 계정 탈취)",
            target_asset="SCADA Gateway (172.16.50.1:3389) & Backup NAS",
            created_at=datetime.now() - timedelta(minutes=15),
            event_ids=["EVT-C-301", "EVT-C-302", "EVT-C-303"],
            evidences=[
                "심야 시간대(03:14) 비정상 원격 데스크톱(RDP) 접속 (+2점)",
                "특권 프로세스(cmd.exe /c vssadmin delete shadows /all /quiet) 호출 (+4점)",
                "백업 스토리지(172.16.50.200:445) 대상 대량 파일 속성 변경 시도 (+2점)",
                "랜섬웨어(LockBit 유사) 암호화 선행 킬체인 프로파일 일치 (+4점)"
            ],
            network_hops=[
                NetworkHop(from_node="Compromised PC (172.16.50.88)", to_node="SCADA Gateway (172.16.50.1)", port=3389, hop_type="attack"),
                NetworkHop(from_node="SCADA Gateway (172.16.50.1)", to_node="Backup Storage (172.16.50.200)", port=445, hop_type="attack"),
            ],
            soar_actions=[
                "SCADA Gateway 및 공정 단말 즉시 네트워크 논리적 격리(VLAN 차단)",
                "백업 스토리지 Read-Only 모드 긴급 강제 전환",
                "OT 운영팀 및 CISO 긴급 SMS/Slack 비상 소집 전파"
            ]
        )

        # 4. INC-004 (HIGH: 사내 SSL-VPN 인증 정보 탈취 후 Tor 출구 노드 경유 관리자 API 대량 호출)
        inc_4 = Incident(
            incident_id="INC-004",
            title="사내 SSL-VPN 인증 정보 탈취 후 Tor 출구 노드 경유 관리자 API 대량 호출",
            category=IncidentCategory.CREDENTIAL_STUFFING_VPN,
            severity=Severity.HIGH,
            score=89,
            status=IncidentStatus.ACTIVE,
            summary="5분 내 32개 국가 Tor IP에서 동시 로그인 시도 후 최종 관리자 콘솔 접근하여 사내 전 직원 계정 덤프",
            actor="185.220.101.5 (Tor Exit Node) / user: park_infra",
            target_asset="VPN Gateway (10.0.0.1) & IAM Admin Console",
            created_at=datetime.now() - timedelta(minutes=28),
            event_ids=["EVT-D-401", "EVT-D-402"],
            evidences=[
                "지리적으로 불가능한 이동 거리(Impossible Travel) 로그인 감지 (+2점)",
                "Tor Exit Node 알려진 IP 대역(185.220.101.0/24) 일치 (+2점)",
                "로그인 직후 IAM API(/api/v1/users/export) 비인가 대량 호출 (+4점)"
            ],
            network_hops=[
                NetworkHop(from_node="Tor Network (185.220.101.5)", to_node="VPN Gateway (10.0.0.1)", port=443, hop_type="attack"),
                NetworkHop(from_node="VPN Gateway (10.0.0.1)", to_node="IAM Console (10.0.0.8)", port=8443, hop_type="lateral"),
            ],
            soar_actions=[
                "Tor 출구 노드 전체 IP 대역 자동 블랙리스트 등록",
                "park_infra 계정 MFA 강제 재설정 및 OTP 토큰 파기",
                "VPN 동시 접속 세션 전면 강제 종료"
            ]
        )

        # 5. INC-005 (HIGH: 개발자 GitHub 저장소 AWS IAM Key 노출 및 S3 비정상 대량 다운로드)
        inc_5 = Incident(
            incident_id="INC-005",
            title="개발자 GitHub 저장소 AWS IAM Key 노출 및 S3 비정상 대량 다운로드",
            category=IncidentCategory.CLOUD_API_KEY_LEAK,
            severity=Severity.HIGH,
            score=93,
            status=IncidentStatus.ACTIVE,
            summary="커밋 20분 후 미인가 해외 IP에서 GetObject API 12,000회 호출하여 82GB 비식별화 이전 원천 데이터 다운로드",
            actor="54.239.28.12 (AWS External Region / Key: AKIA_DEV_SYNC)",
            target_asset="AWS S3: s3://corp-analytics-data-prod",
            created_at=datetime.now() - timedelta(minutes=45),
            event_ids=["EVT-E-501", "EVT-E-502"],
            evidences=[
                "GitHub Public 커밋 내 AWS Access Key Signature 매칭 (+2점)",
                "인가되지 않은 해외 AWS 리전 IP(eu-central-1)에서 API 서명 호출 (+2점)",
                "평시 대비 450배 폭증한 S3 아웃바운드 트래픽(82GB) 전송 감지 (+4점)"
            ],
            network_hops=[
                NetworkHop(from_node="Developer PC", to_node="GitHub Repo", port=443, hop_type="normal"),
                NetworkHop(from_node="Attacker IP (54.239.28.12)", to_node="AWS S3 Storage", port=443, hop_type="exfiltration"),
            ],
            soar_actions=[
                "노출된 AWS IAM Access Key 즉시 비활성화(Deactivate)",
                "해당 S3 버킷 임시 퍼블릭/외부 접근 완전 차단(Bucket Policy 차단)",
                "GitGuardian 연계 커밋 이력 롤백 및 시크릿 스캐닝 감사"
            ]
        )

        # 6. INC-006 (CRITICAL: 사내 그룹웨어 Log4j 취약점 악용 웹쉘 업로드 및 비콘 통신)
        inc_6 = Incident(
            incident_id="INC-006",
            title="사내 그룹웨어 Log4j 취약점(CVE-2021-44228) 악용 웹쉘 업로드 및 비콘 통신",
            category=IncidentCategory.WEBSHELL_RCE,
            severity=Severity.CRITICAL,
            score=97,
            status=IncidentStatus.ACTIVE,
            summary="HTTP User-Agent에 JNDI 인젝션 유입 후 /uploads 디렉토리에 웹쉘 생성 및 30초 주기 C2 비콘 수신",
            actor="103.145.13.91 (Cobalt Strike C2)",
            target_asset="Groupware Server (10.0.0.15:8080 / /upload/shell.jsp)",
            created_at=datetime.now() - timedelta(hours=1, minutes=10),
            event_ids=["EVT-F-601", "EVT-F-602", "EVT-F-603"],
            evidences=[
                "JNDI LDAP 룩업 페이로드(${jndi:ldap://...}) 감지 (+4점)",
                "그룹웨어 파일시스템 상에 신규 JSP 파일(shell.jsp) 생성 (+2점)",
                "30초 간격 주기적 외부 C2 하트비트 트래픽(Cobalt Strike Sleep Mask) 포착 (+4점)"
            ],
            network_hops=[
                NetworkHop(from_node="Attacker IP (103.145.13.91)", to_node="Groupware (10.0.0.15)", port=8080, hop_type="attack"),
                NetworkHop(from_node="Groupware (10.0.0.15)", to_node="External C2 (103.145.13.91)", port=443, hop_type="exfiltration"),
            ],
            soar_actions=[
                "WAF에 JNDI/Log4j 패턴 차단 시그니처 배포",
                "그룹웨어 서버 즉시 네트워크 격리 및 악성 jsp 파일 격리/삭제",
                "서버 JVM 패치 버전 긴급 업데이트"
            ]
        )

        # 7. INC-007 (MEDIUM: 퇴사 예정 연구원의 대용량 WeTransfer 핵심 소스코드 반출 시도)
        inc_7 = Incident(
            incident_id="INC-007",
            title="퇴사 예정 연구원의 대용량 WeTransfer 익명 전송을 통한 핵심 소스코드 반출 시도",
            category=IncidentCategory.INSIDER_DATA_THEFT,
            severity=Severity.MEDIUM,
            score=82,
            status=IncidentStatus.CONTAINED,
            summary="사내 깃랩에서 코어 알고리즘 zip 아카이빙 후 wetransfer.com 질의 및 420MB 일회성 대용량 전송 시도",
            actor="192.168.30.12 (choi_research)",
            target_asset="GitLab: repo_core_algo.zip -> wetransfer.com",
            created_at=datetime.now() - timedelta(hours=1, minutes=45),
            event_ids=["EVT-G-701", "EVT-G-702"],
            evidences=[
                "사내 소스코드 리포지토리 일괄 아카이빙(zip) 다운로드 감지 (+2점)",
                "사내 차단 권고 SaaS인 wetransfer.com DNS 질의 포착 (+2점)",
                "420 MB 대용량 아웃바운드 파일 업로드 시도 (DLP 정책 위반, +4점)"
            ],
            network_hops=[
                NetworkHop(from_node="Research PC (192.168.30.12)", to_node="GitLab Server (10.0.0.25)", port=443, hop_type="normal"),
                NetworkHop(from_node="Research PC (192.168.30.12)", to_node="WeTransfer Cloud", port=443, hop_type="suspicious"),
            ],
            soar_actions=[
                "프록시/방화벽에서 WeTransfer 업로드 세션 즉시 차단(RST 패킷)",
                "연구원 단말 외장 매체 및 클라우드 업로드 권한 일시 회수",
                "사내 감사팀(정보보호팀) 보안 감사 보고서 자동 발행"
            ]
        )

        # 8. INC-008 (HIGH: 인사평가 위장 피싱 메일 악성 매크로 실행 및 Active Directory 정찰)
        inc_8 = Incident(
            incident_id="INC-008",
            title="인사평가 위장 피싱 메일 악성 매크로 실행 및 Active Directory(AD) 정찰",
            category=IncidentCategory.PHISHING_MACRO_RECON,
            severity=Severity.HIGH,
            score=88,
            status=IncidentStatus.ACTIVE,
            summary="'2026_상반기_인사평가결과.xlsm' 열람 후 powershell.exe 기동하여 도메인 컨트롤러(389) 대량 질의",
            actor="192.168.10.105 (lee_hr_pc)",
            target_asset="Domain Controller (10.0.0.5:389 LDAP)",
            created_at=datetime.now() - timedelta(hours=2, minutes=20),
            event_ids=["EVT-H-801", "EVT-H-802"],
            evidences=[
                "오피스 프로세스(EXCEL.EXE)에서 자식 프로세스로 PowerShell.exe 무단 실행 (+4점)",
                "BloodHound/ADFind 유사 도메인 객체 대량 LDAP 질의 포착 (+2점)",
                "발신자 도메인 SPF/DKIM 변조된 스피어피싱 이메일 추적 (+2점)"
            ],
            network_hops=[
                NetworkHop(from_node="External Mail Server", to_node="HR PC (192.168.10.105)", port=25, hop_type="suspicious"),
                NetworkHop(from_node="HR PC (192.168.10.105)", to_node="Domain Controller (10.0.0.5)", port=389, hop_type="attack"),
            ],
            soar_actions=[
                "피싱 메일 발신 도메인 차단 및 사내 수신 메일함 일괄 격리",
                "감염 PC(192.168.10.105) EDR 네트워크 완전 격리 실행",
                "도메인 관리자 계정 패스워드 일괄 강제 변경"
            ]
        )

        # 9. INC-009 (MEDIUM: 사내 유휴 GPU 개발 서버 침투 후 비인가 가상화폐 채굴 구동)
        inc_9 = Incident(
            incident_id="INC-009",
            title="사내 유휴 GPU 개발 서버 침투 후 비인가 가상화폐 채굴(Cryptomining) 구동",
            category=IncidentCategory.CRYPTOMINING_INTRUSION,
            severity=Severity.MEDIUM,
            score=79,
            status=IncidentStatus.RESOLVED,
            summary="Docker REST API(:2375) 침투로 XMRig 이미지 무단 기동 및 xmr.pool.minergate.com 질의 감지",
            actor="45.142.122.90 -> Docker Daemon (10.0.0.80:2375)",
            target_asset="GPU Server (10.0.0.80 / NVIDIA RTX 4090)",
            created_at=datetime.now() - timedelta(hours=3, minutes=40),
            event_ids=["EVT-I-901", "EVT-I-902"],
            evidences=[
                "외부 비인가 IP에서 Docker Remote API 인증 없는 컨테이너 생성 (+4점)",
                "가상화폐 채굴 풀(xmr.pool.minergate.com) DNS 질의 및 포트 3333 트래픽 (+2점)",
                "GPU 코어 사용률 및 전력 소모 99.8% 급증 (+2점)"
            ],
            network_hops=[
                NetworkHop(from_node="Attacker IP (45.142.122.90)", to_node="GPU Server (10.0.0.80)", port=2375, hop_type="attack"),
                NetworkHop(from_node="GPU Server (10.0.0.80)", to_node="Mining Pool Cloud", port=3333, hop_type="suspicious"),
            ],
            soar_actions=[
                "XMRig 악성 도커 컨테이너 강제 중지 및 이미지 영구 삭제",
                "Docker 데몬 포트(2375) 외부 바인딩 해제 및 TLS 상호인증 활성화",
                "채굴 풀 관련 DNS 도메인/IP 방화벽 차단"
            ]
        )

        # 10. INC-010 (LOW: 외주 협력사 유지보수 단말의 비인가 내부 서브넷 포트 스캔)
        inc_10 = Incident(
            incident_id="INC-010",
            title="외주 협력사 유지보수 단말의 비인가 내부 서브넷 포트 스캔 및 SMB 취약점 탐색",
            category=IncidentCategory.UNAUTHORIZED_PORT,
            severity=Severity.LOW,
            score=62,
            status=IncidentStatus.RESOLVED,
            summary="할당된 유지보수 범위를 벗어나 내부 코어 서브넷 254개 IP를 대상으로 SMB:445, RDP:3389 SYN 스캔 수행",
            actor="192.168.99.20 (vendor_partner_laptop)",
            target_asset="10.0.0.0/24 Core Network",
            created_at=datetime.now() - timedelta(hours=5),
            event_ids=["EVT-J-1001"],
            evidences=[
                "게스트 유지보수 VLAN에서 사내 코어 VLAN으로의 비인가 세션 시도 (+2점)",
                "10초 내 254개 연속 IP에 대한 SMB(445), RDP(3389) SYN 패킷 감지 (+4점)"
            ],
            network_hops=[
                NetworkHop(from_node="Vendor PC (192.168.99.20)", to_node="Internal Core Firewall", port=445, hop_type="suspicious"),
            ],
            soar_actions=[
                "협력사 IP(192.168.99.20) 내부망 접근 일시 차단",
                "외주 전담 관리자에게 비인가 스캔 경고 통보",
                "원격 유지보수 세션 감사 로그 추출"
            ]
        )

        # 10개 인시던트 등록
        for inc in [inc_1, inc_2, inc_3, inc_4, inc_5, inc_6, inc_7, inc_8, inc_9, inc_10]:
            self.incidents[inc.incident_id] = inc

    def ingest_events(self, events: List[SecurityEvent]):
        """이벤트 버퍼에 이벤트 추가 및 상관분석 수행"""
        self.event_buffer.extend(events)
        self.event_buffer.sort(key=lambda e: e.timestamp)
        self._analyze_buffer()

    def _analyze_buffer(self):
        """버퍼 내 이벤트를 슬라이딩 윈도우로 순회하며 패턴 감지"""
        # 현재는 정의된 모의 시나리오가 이미 정교하게 Incident로 매핑되어 있으므로
        # 실시간 이벤트 유입 시 버퍼 상태를 동기화합니다.
        pass

    def get_all_incidents(self) -> List[Incident]:
        """최신 발생 순서로 인시던트 목록 반환"""
        return sorted(list(self.incidents.values()), key=lambda x: x.created_at, reverse=True)

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        return self.incidents.get(incident_id)

    def update_incident_status(self, incident_id: str, new_status: IncidentStatus):
        if incident_id in self.incidents:
            self.incidents[incident_id].status = new_status
