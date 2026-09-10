"""
NexusGuard - Memory Store
시스템 상태 및 싱글톤 인스턴스 관리 저장소

[이 파일이 하는 일]
프로그램이 켜질 때 딱 한 번 실행되는 '초기 준비' 코드다.
엔진 객체를 만들고, 초기 이벤트를 엔진에 밀어 넣는다.

[싱글톤(Singleton)이란]
객체를 딱 하나만 만들어서 프로그램 전체가 공유하는 방식이다.
Streamlit은 사용자가 버튼을 누를 때마다 화면 코드를 처음부터 다시 실행하는데,
그때마다 엔진을 새로 만들면 지금까지 쌓인 분석 상태가 전부 날아간다.
그래서 get_instance()로 "이미 만들어둔 게 있으면 그걸 그대로 쓴다"고 처리한다.

[수정됨 — 실데이터가 엔진에 들어가지 않던 문제를 고쳤다]
예전에는 두 종류의 이벤트를 이렇게 다뤘다.

  1) initial_events (더미 로그)  → correlation_engine.ingest_events() 로 투입됨 ✅
  2) team_events   (실제 수집 로그) → governance_engine 에만, 그것도 DNS 소스만 투입됨 ⚠

문제는 team_collector가 만들어내는 이벤트의 log_source가
WINDOWS_AGENT 또는 CHROME_EXTENSION 뿐이고 DNS는 없다는 점이었다.
따라서 `if ev.log_source == LogSource.DNS:` 조건은 항상 거짓이 되어
실제 수집 로그가 결국 어느 엔진에도 들어가지 않았다.
즉 화면에 보이는 WATCH/HIGH 판정이 전부 더미 데이터와 시뮬레이션 버튼의 결과였다.

지금은 아래 두 가지로 고쳤다.
  · DNS 조건을 없애고 team_events 를 전부 governance_engine 에 넘긴다
    (process_dns_event 가 내부에서 소스를 판별하므로 그대로 넘겨도 된다)
  · team_events 를 correlation_engine.ingest_events() 에도 넘겨 실제로 판정시킨다
"""

from typing import Optional, TYPE_CHECKING
from nexusguard.generators.dummy_logs import get_all_initial_events
from nexusguard.schemas.event import LogSource

# TYPE_CHECKING 은 '타입 힌트를 쓸 때만' import 하겠다는 뜻이다.
# 실행 시점에는 import 되지 않으므로 순환 참조(서로가 서로를 import) 문제를 피할 수 있다.
if TYPE_CHECKING:
    from nexusguard.engine.correlation import CorrelationEngine
    from nexusguard.engine.governance import ShadowAIGovernanceEngine


class AppContext:
    """
    엔진들을 담고 있는 그릇. 프로그램 전체에서 이 객체 하나만 존재한다.

    _instance 에 만들어진 객체를 보관해두고,
    get_instance()가 호출될 때마다 그것을 돌려준다.
    """

    _instance: Optional["AppContext"] = None

    def __init__(self):
        # 함수 안에서 import 하는 이유:
        # 파일 맨 위에서 import 하면 correlation.py ↔ memory_store.py 가
        # 서로를 부르는 순환 참조가 생길 수 있어 실행 시점으로 미룬 것이다.
        from nexusguard.engine.correlation import CorrelationEngine
        from nexusguard.engine.governance import ShadowAIGovernanceEngine

        # --- 1. 엔진 두 개 생성 ---
        self.correlation_engine = CorrelationEngine()      # 위험 상태 판정 담당
        self.governance_engine = ShadowAIGovernanceEngine()  # 섀도우 AI 자산 관리 담당

        # --- 2. 시연용 더미 이벤트 생성 ---
        self.initial_events = get_all_initial_events()

        # --- 3. 더미 이벤트를 각 엔진에 투입 ---
        # 대시보드를 처음 켰을 때 화면이 텅 비어 있지 않도록 미리 채워 넣는 용도다.
        self.correlation_engine.ingest_events(self.initial_events)
        for ev in self.initial_events:
            self.governance_engine.process_dns_event(ev)

        # --- 4. 팀원들의 실제 에이전트 및 DB 이벤트 피딩 ---
        #   Railway 서버가 꺼져 있거나 네트워크가 안 될 수도 있으므로 try로 감싼다.
        #   실패해도 대시보드 자체는 떠야 하기 때문이다.
        try:
            from nexusguard.collectors.team_collector import get_team_security_events
            self.team_events = get_team_security_events()

            # [수정됨] 예전에는 log_source == LogSource.DNS 인 것만 골라 넘겼는데
            #   team_collector 는 DNS 이벤트를 아예 만들지 않아 항상 0건이었다.
            #   이제 전부 넘긴다. 소스 판별은 process_dns_event 안에서 한다.
            for ev in self.team_events:
                self.governance_engine.process_dns_event(ev)

            # [추가됨] 상관분석 엔진에도 넣어 실제 로그로 상태 전이가 일어나게 한다.
            #   get_team_security_events() 는 최신순(내림차순)으로 돌려주는데
            #   상관분석은 "DB 조회 → AI 접속" 시간 순서가 맞아야 성립하므로
            #   넘기기 전에 timestamp 오름차순으로 정렬한다.
            self.correlation_engine.ingest_events(
                sorted(self.team_events, key=lambda e: e.timestamp)
            )
        except Exception as e:
            # 수집 실패 시 빈 리스트로 두고 계속 진행한다 (프로그램을 멈추지 않는다)
            self.team_events = []

    @classmethod
    def get_instance(cls) -> "AppContext":
        """
        이미 만들어진 AppContext가 있으면 그것을, 없으면 새로 만들어 돌려준다.

        ⚠ 한 번 만들어지면 다시 __init__ 이 실행되지 않으므로,
          위 4번의 실데이터 조회도 프로그램 시작 시 딱 한 번만 일어난다.
          이후 새로 올라온 로그는 여기서 자동으로 반영되지 않는다.
          (5초 폴링 시점에 ingest_events 를 다시 호출하려면 ui/app.py 쪽 작업이 필요하다.
           중복 투입 자체는 CorrelationEngine 이 event_id 로 걸러주므로 안전하다.)
        """
        if cls._instance is None:
            cls._instance = AppContext()
        return cls._instance


def get_context() -> AppContext:
    """화면 코드에서 엔진에 접근할 때 쓰는 짧은 함수. ctx = get_context() 형태로 사용한다."""
    return AppContext.get_instance()
