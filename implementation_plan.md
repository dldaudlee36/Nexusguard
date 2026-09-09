# NexusGuard 잔여 작업 구현 계획

## 구현 대상 작업

### P0-1: DB CSV 파서 (`load_db_audit_csv`) 연동
- `team_collector.py`에 `load_db_audit_csv()` 함수 추가
- CSV 컬럼: `event_time, user_name, src_ip, action, target_table, query_string, rows_affected`
- `get_team_security_events()`에서 통합하여 `LogSource.DB` 이벤트 주입

### P0-2: Chrome 확장 프로그램 강화
- `content.js`에 drag-and-drop(`ondrop`), paste(`paste`) 이벤트 후킹 추가
- 이벤트 타입별(`FILE_UPLOAD_ATTEMPT`, `PASTE_ATTEMPT`) 구분 전송

### P1: 사용자 계정 매핑 테이블
- `team_collector.py`에 `USER_HOST_MAPPING` 딕셔너리 추가
- DB 유저(`test_user`)와 Windows 에이전트 계정(`User`) 연결

### P1: agent.py 로컬 버퍼 (Queue)
- 네트워크 단절 시 `data/agent_queue.jsonl` 파일에 이벤트 임시 저장
- 다음 전송 사이클에서 버퍼 재전송 시도 후 성공 시 큐 소진
