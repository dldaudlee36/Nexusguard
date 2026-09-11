# v3 검증 기록 — 2026-09-09

- 확장 JavaScript 테스트: 본문 미전송, 글자 수(유니코드 포함), 중복 등록 방지, 암호창·합성 이벤트 제외, 파일 선택 다중 처리 통과.
- Agent HTTP 테스트: 정상 저장, 잘못된 메타데이터 거부, 실제 전송 실패 시 502, 본문 필드 차단 통과.
- 빌드한 EXE 실행 후 로컬 HTTP 붙여넣기 메타데이터 → 운영 Railway → 대시보드 수집기 검증 통과.
- 운영 테스트 기록: ID 14157, PASTE_ATTEMPT, 글자 수 29, 서버 시각 Wed, 09 Sep 2026 08:25:49 GMT. 대상은 nexusguard-paste-test.invalid 테스트 표시용 도메인.
- Streamlit AppTest: 실서버 붙여넣기 로그와 글자 수 표시, 이벤트 필터, 기존 네 메뉴 정상 렌더링 통과.
- 브라우저에서 기존 대시보드 렌더링과 수집 표시 확인.

브라우저 자동화 입력은 isTrusted=false 합성 붙여넣기로 발생해 확장의 의도된 필터로 제외되었습니다. 따라서 실제 설치된 Chrome v3에서 사람의 붙여넣기까지 이어지는 최종 테스트는 확장 업데이트·사이트 새로고침 후 확인해야 합니다. 앞선 Chrome 콘솔 감지는 사용자가 확인한 상태이며, 이번 서버 연동 검증은 빌드된 Agent의 실제 HTTP 입력으로 수행했습니다.


## 3.1 추가 검증

원인 조사 당시 Agent 3.0.0과 대시보드는 정상 실행 중이었으나 사용자의 ChatGPT 붙여넣기 요청은 Agent까지 도착하지 않았습니다. Chrome 등록 폴더는 바탕화면 guard/browser_extension이 맞았습니다. 실제 Chrome 콘솔을 직접 읽을 수 없으므로 확장 재로드 누락과 페이지 측 네트워크 제한 중 어느 것이 실제 원인인지는 확정하지 않았습니다.

웹페이지 content script의 직접 HTTP 요청을 제거하고, host_permissions를 로컬 127.0.0.1로 제한한 확장 service worker를 통해 전송하도록 수정했습니다. 고정 endpoint만 허용하고 붙여넣기 본문 필드는 worker와 Agent에서 모두 차단합니다.
참고: https://developer.chrome.com/docs/extensions/develop/concepts/network-requests

자동 테스트는 content → worker 메시지 처리, 저장 결과 전달, 실패 상태, 암호창·합성 이벤트 제외, 본문 미전송, 대상 호스트 검증, 다중 파일 처리를 통과했습니다. 실제 worker 소스의 HTTP → 실행 중 Agent → Railway 성공 응답도 확인했습니다. Chrome runtime 메시지 전달은 테스트에서 모의했으며 실제 설치 Chrome 입력 테스트와 구분합니다.
