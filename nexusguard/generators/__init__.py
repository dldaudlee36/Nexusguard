# generators 패키지
# 시연·검증용 가짜 로그를 만들어내는 모듈 모음.
# 실제 수집 로그가 아니라는 점에 주의.

from .dummy_logs import (
    generate_scenario_a_logs,
    generate_scenario_b_logs,
    generate_background_dns_logs,
    get_all_initial_events,
)

__all__ = [
    "generate_scenario_a_logs",
    "generate_scenario_b_logs",
    "generate_background_dns_logs",
    "get_all_initial_events",
]
