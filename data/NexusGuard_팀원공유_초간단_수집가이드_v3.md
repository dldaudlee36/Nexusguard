# NexusGuard 초간단 사용 가이드

## 1. 지금 잡는 로그

- `WEB_ACCESS`  
  → 사이트 접속 흔적  
  → `windows-agent`가 수집

- `FILE_UPLOAD_ATTEMPT`  
  → 사이트에서 파일 첨부/선택 시도  
  → Chrome 확장프로그램이 감지  
  → **업로드 완료가 아니라 첨부 시도 로그**

## 2. 작동 원리

```text
사이트 접속
→ Agent
→ WEB_ACCESS

파일 첨부 시도
→ Chrome 확장프로그램
→ Agent
→ FILE_UPLOAD_ATTEMPT

둘 다
→ Railway
→ PostgreSQL 저장
→ 분석팀 / UI가 사용
```

## 3. PC 구분

두 로그 모두 아래 값이 같이 들어감.

```text
pc_name
local_ip
target
event_time
```

분석할 때는 같은 `pc_name + local_ip + 가까운 시간` 기준으로 묶으면 됨.

## 4. 실행 방법

### 4-1. 받은 파일 확인

팀원이 받아야 하는 것은 2개임.

```text
NexusGuardAgent.exe
browser_extension 폴더
```

`browser_extension` 폴더 안에는 최소한 아래 파일이 있어야 함.

```text
manifest.json
content.js
```

### 4-2. Agent 실행

1. `NexusGuardAgent.exe`를 더블클릭
2. 검은 창이 열리면 끄지 말고 그대로 켜둠
3. 정상 실행되면 대략 아래처럼 보임

```text
NexusGuard Agent 시작
사용자: User
PC 이름: DESKTOP-XXXX
로컬 IP: 192.168.x.x
Chrome 확장 연결 대기: http://127.0.0.1:8765
새로운 사이트 접속 감시 중...
```

4. 사이트를 새로 접속하면 아래처럼 나올 수 있음

```text
[새 사이트 감지] chatgpt.com
[서버 전송 성공] WEB_ACCESS chatgpt.com
```

### 4-3. Chrome 확장프로그램 설치

1. Chrome 실행
2. 주소창에 아래 입력

```text
chrome://extensions/
```

3. 오른쪽 위 **개발자 모드** ON
4. **압축해제된 확장 프로그램을 로드** 클릭
5. 전달받은 `browser_extension` 폴더 선택  
   경로 예시: `C:\Users\User\Desktop\guard\browser_extension`
6. `NexusGuard Upload Detector`가 보이면 설치 완료
7. 기존에 열어둔 ChatGPT / Gmail / Gemini 페이지는 **F5 새로고침**

### 4-4. 파일 첨부 시도 테스트

1. Agent가 실행 중인지 확인
2. ChatGPT / Gmail / Gemini 중 하나 접속
3. 파일 첨부 버튼 클릭
4. 아무 파일 하나 선택
5. Agent 창에 아래처럼 나오면 성공

```text
[파일 업로드 시도 감지]
사이트: chatgpt.com
파일명: report.pdf
파일 크기: 86058
PC: DESKTOP-XXXX
로컬 IP: 192.168.x.x

[서버 전송 성공] FILE_UPLOAD_ATTEMPT chatgpt.com
```

### 4-5. 주의

- Agent를 끄면 파일 첨부 시도 로그가 서버로 전달되지 않음
- 확장프로그램 코드를 수정했으면 `chrome://extensions/`에서 확장프로그램 새로고침 필요
- 확장프로그램 새로고침 후 테스트 사이트도 F5 필요
- 현재 확인된 사이트: ChatGPT, Gmail, Gemini
- 네이버 메일처럼 커스텀 업로드 방식은 감지가 안 될 수 있음

## 5. 로그 읽는 법

예:

```text
event_type = WEB_ACCESS
source = windows-agent
target = chatgpt.com
```

→ ChatGPT 접속 흔적

```text
event_type = FILE_UPLOAD_ATTEMPT
source = chrome-extension
target = chatgpt.com
```

→ ChatGPT에서 파일 첨부 시도

같은 PC인지 볼 때는 아래 값을 같이 확인.

```text
pc_name
local_ip
event_time
```
