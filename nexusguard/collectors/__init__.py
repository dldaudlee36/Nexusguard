# collectors 패키지
# 바깥에서 들어오는 로그(Railway 서버, 로컬 파일)를 SecurityEvent 형태로 바꾸는 변환기 모음.
# 아래 import 덕분에 다른 파일에서
#   from nexusguard.collectors import fetch_railway_events
# 처럼 짧게 쓸 수 있다. (team_collector 까지 적지 않아도 된다)

from .team_collector import (
    fetch_railway_events, fetch_activity_log_events, get_team_security_events,
    get_team_sim_scenarios, load_team_guide_markdown,
    set_railway_collection_enabled, is_railway_collection_enabled
)
