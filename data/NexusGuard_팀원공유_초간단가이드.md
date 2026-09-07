# NexusGuard 팀원 공유용 초간단 가이드

> **한 줄 요약:**  
> 각 PC에서 `NexusGuardAgent.exe`를 켜두면 사이트 접속 기록이 자동으로 중앙 서버에 쌓이고,  
> 팀원이 만든 Streamlit UI는 그 기록을 받아서 화면에 보여주면 됩니다.

---

## 1. 지금 내가 만들어 둔 것

현재 아래 흐름까지 동작합니다.

```text
사용자 PC
  ↓
NexusGuardAgent.exe 실행
  ↓
사이트 접속 자동 감지
  ↓
인터넷으로 중앙 서버에 전송
  ↓
Railway에 있는 Flask 서버가 받음
  ↓
PostgreSQL의 events 테이블에 저장
```

즉, **로그 파일을 직접 업로드하거나 서로 파일을 주고받을 필요가 없습니다.**

다른 PC에서도 `NexusGuardAgent.exe`를 실행하면 그 PC의 접속 기록이 같은 중앙 서버에 쌓이는 것까지 테스트했습니다.

---

## 2. 지금 저장되는 로그는 이런 내용

예를 들면 아래 정보가 저장됩니다.

```text
시간
사용자 이름
PC 이름
이벤트 종류
접속한 사이트
위험 점수
```

예시:

```text
2026-09-07 11:38
User
DESKTOP-XXXX
WEB_ACCESS
chatgpt.com
0
```

현재 위험 점수는 아직 분석 기능을 붙이지 않았기 때문에 대부분 `0`입니다.

---

## 3. 팀원이 만든 Streamlit UI에는 뭘 연결하면 되나?

### 기존

```text
더미 로그
  ↓
Streamlit UI
```

### 앞으로

```text
Railway에 쌓인 실제 로그
  ↓
/events 주소로 가져오기
  ↓
Streamlit UI
```

즉, **UI에서 더미로그를 읽는 부분만 실제 로그를 받아오는 코드로 바꾸면 됩니다.**

팀원에게 이렇게 말하면 됩니다.

> **“지금 UI에서 더미로그 쓰는 부분 대신 내가 만든 `/events` API에서 실제 로그를 받아오도록 연결해줘.”**

---

## 4. 실제 로그를 가져오는 코드

Streamlit 코드 안에서 아래처럼 사용하면 됩니다.

```python
import requests

url = "https://bountiful-nature-production-22ec.up.railway.app/events"

headers = {
    "X-API-Key": "20110313"
}

response = requests.get(
    url,
    headers=headers,
    timeout=5
)

response.raise_for_status()

logs = response.json()
```

이제 `logs` 안에 중앙 서버에 쌓인 실제 로그 목록이 들어옵니다.

예:

```python
[
    {
        "pc_name": "DESKTOP-XXXX",
        "event_type": "WEB_ACCESS",
        "target": "chatgpt.com",
        "risk_score": 0
    }
]
```

그다음 기존 Streamlit UI가 더미 데이터 대신 이 `logs`를 사용하면 됩니다.

---

## 5. 그러면 팀원에게 뭘 주면 되나?

### UI 연결 담당자에게

1. 현재 프로젝트 소스 폴더
2. 로그 조회 주소
3. 팀 API Key

로그 조회 주소:

```text
https://bountiful-nature-production-22ec.up.railway.app/events
```

현재 팀 테스트용 API Key는 **`20110313`** 입니다.

### 로그 수집 테스트만 하는 사람에게

```text
NexusGuardAgent.exe
```

이 파일만 주면 됩니다.

실행해 둔 상태에서 사이트에 접속하면 자동으로 중앙 서버에 기록됩니다.

---

## 6. Railway는 뭐 하는 곳인가?

Railway는 어렵게 생각할 필요 없습니다.

> **우리 팀의 중앙 서버와 DB가 인터넷에 올라가 있는 곳**

이라고 보면 됩니다.

Railway가 사이트를 감지하는 것은 아닙니다.

역할은 이렇게 나뉩니다.

```text
NexusGuardAgent.exe
= 각 PC에서 사이트 접속 감지

Flask
= Agent가 보낸 로그 받기

PostgreSQL
= 받은 로그 저장

Railway
= Flask와 PostgreSQL을 인터넷에서 계속 실행해 주는 곳

Streamlit UI
= 저장된 로그를 가져와 관리자에게 보여주는 화면
```

---

## 7. 전체 구조를 진짜 쉽게 보면

```text
[사용자 PC]
크롬으로 사이트 접속
      ↓
NexusGuardAgent.exe
"chatgpt.com 접속했음"
      ↓
      ↓ 인터넷
      ↓
[Railway]
Flask가 기록 받음
      ↓
PostgreSQL에 저장
      ↓
      ↓ /events로 로그 전달
      ↓
[Streamlit UI]
실제 로그 화면 표시
```

---

## 8. 지금 팀원이 해야 할 일

UI 담당자는 서버를 새로 만들 필요 없습니다.

딱 이것만 하면 됩니다.

```text
1. 기존 Streamlit UI에서 더미로그 읽는 부분 찾기
2. 위 requests 코드로 실제 로그 받기
3. response.json() 결과를 기존 UI 데이터 자리에 넣기
4. 실제 로그가 화면에 뜨는지 확인
```

---

# 용어 정리

| 용어 | 쉽게 말하면 |
|---|---|
| **Agent** | 사용자 PC에서 사이트 접속을 감지하는 프로그램 |
| **NexusGuardAgent.exe** | 우리가 배포할 로그 수집 프로그램 |
| **Railway** | 우리 서버를 인터넷에서 계속 켜두는 곳 |
| **Flask** | Agent가 보낸 로그를 받아주는 프로그램 |
| **PostgreSQL** | 로그를 저장하는 데이터베이스 |
| **events 테이블** | 실제 수집 로그가 쌓이는 표 |
| **API** | 프로그램끼리 데이터를 주고받는 통로 |
| **`/events`** | UI가 실제 로그를 가져오는 주소 |
| **API Key** | 우리 팀만 로그를 볼 수 있게 확인하는 비밀번호 같은 값 |
| **JSON** | 로그를 프로그램끼리 주고받기 편하게 정리한 형태 |
| **Streamlit** | 팀원이 만든 관리자용 화면(UI) |

---

## 팀원에게 그대로 보내도 되는 설명

> **지금 각 PC에서 NexusGuardAgent.exe를 실행하면 사이트 접속 기록이 Railway 중앙 서버에 자동으로 저장돼요.  
> UI 쪽에서는 기존 더미로그 대신 `GET /events`로 실제 로그를 받아서 화면에 연결하면 됩니다.  
> Railway를 직접 만질 필요는 없고, API 주소와 API Key(`20110313`)는 아래 문서에 같이 적어뒀어요.**
