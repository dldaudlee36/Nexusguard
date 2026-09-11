이번 배포는 v3.1입니다. Agent는 3.0.0, Chrome 확장은 3.1.0입니다.
ChatGPT에서 감지한 기록은 확장 백그라운드에서 로컬 Agent로 전송합니다.
기존 확장 폴더를 업데이트했다면 chrome://extensions → NexusGuard 새로고침(↻) → ChatGPT 탭 F5가 필요합니다.
Chrome 퍼즐 아이콘 → NexusGuard Upload Detector를 누르면 Agent 연결 상태와 마지막 붙여넣기 저장 결과를 볼 수 있습니다.
저장 완료인데 대시보드에 없으면 수집 ON, IP 필터 전체, 이벤트 필터 PASTE_ATTEMPT를 확인하세요. 최신 100건 밖으로 밀려난 기록은 현재 API 조회에 보이지 않습니다.

# v3 업데이트

1. 이전 전달 폴더에서 `stop-all.bat` 실행. 별도로 실행한 이전 Agent 창도 종료.
2. `NexusGuard-Team-v3.1.zip`을 새 폴더에 전체 압축 해제.
3. 관리자: `start-dashboard.bat`, 사용자: `start-agent.bat`, 둘 다: `start-all.bat` 실행.
4. 사용자 PC의 Chrome 확장을 이번 `browser_extension` 폴더로 등록하고 버전 3.1.0 확인. 사이트 새로고침.
5. 관리자 대시보드 → 중앙 서버 파이프라인 → 수집 ON → PASTE_ATTEMPT 필터.

팀원 저장소 64b6a908e21ec1233ce055112455be7e428348f3 기준 최신 화면을 반영했습니다. 기존 네 메뉴를 유지하며 붙여넣기 글자 수와 이벤트 필터를 추가했습니다. 대시보드 실행을 막던 Any import 누락도 수정했습니다.
붙여넣기를 파일 업로드로 잘못 분류하지 않도록 수정했습니다. API 키 설정과 휴대용 실행 환경을 포함했습니다. 서버 재배포는 필요 없습니다.

이 PC의 바탕화면 `guard/browser_extension`에도 새 파일을 반영했습니다. 그 폴더를 이미 등록했다면 Chrome에서 확장 새로고침 후 사이트 새로고침만 하면 됩니다. 실제 등록 경로가 다르면 이번 배포 폴더로 다시 등록하세요.
