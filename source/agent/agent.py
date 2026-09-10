"""
NexusGuard Windows Agent (NexusGuardAgent.exe 의 소스)

=====================================================================
[이 프로그램이 하는 일]
=====================================================================
직원 PC에서 백그라운드로 돌면서 두 가지를 감시하고 중앙 서버로 보낸다.

  1) 새로 접속한 사이트   ─ 윈도우 DNS 캐시를 5초마다 들여다본다
  2) 파일 첨부 시도       ─ 크롬 확장이 알려주는 것을 받아서 전달한다

[전체 그림]
   [크롬 확장]                    [이 프로그램]              [Railway 서버]
   파일 첨부 감지 ──POST:8765──▶  받아서 전달  ──POST──▶  DB 저장
                                       ▲
   윈도우 DNS 캐시 ────────────────────┘ (5초마다 확인)

[동시에 두 가지를 하는 방법 — 스레드]
이 프로그램은 두 가지 일을 동시에 해야 한다.
  · 크롬 확장이 언제 연락할지 모르므로 계속 기다려야 한다
  · 그러면서 5초마다 DNS 캐시도 확인해야 한다

한 줄로 짜면 둘 중 하나만 할 수 있으므로,
확장 대기는 별도 스레드(작업 갈래)에 맡기고
DNS 확인은 메인 흐름에서 반복한다. 파일 맨 아래를 보면 그 구조가 보인다.

[⚠ 개인정보 관련 주의]
아래 get_domains()는 DNS 캐시에 잡히는 '모든' 도메인을 가져온다.
IGNORE_DOMAINS로 걸러지는 것은 수집 서버 자기 자신 하나뿐이다.

즉 업무와 무관한 개인 사이트 접속 기록까지 전부 서버로 올라간다.
감시 대상 도메인 목록을 만들어 그것만 보내도록 좁히는 것이 바람직하다.

또 DNS 캐시에는 사용자가 직접 연 사이트뿐 아니라
광고나 백그라운드 통신으로 조회된 도메인도 섞인다.
따라서 로그에 도메인이 찍혔다고 그 사람이 그 사이트를 열었다고 단정할 수 없다.
"""

import subprocess   # 윈도우 명령(ipconfig) 실행용
import time
import re           # 도메인 형태를 골라내는 정규표현식
import requests     # 서버로 HTTP 전송
import socket       # PC 이름, IP 알아내기
import getpass      # 로그인한 사용자 이름 알아내기
import threading    # 두 가지 일을 동시에 하기 위한 스레드
import json

from http.server import BaseHTTPRequestHandler, HTTPServer


# 로그를 보낼 중앙 수집 서버 주소
SERVER_URL = "https://bountiful-nature-production-22ec.up.railway.app/events"
SERVER_DOMAIN = "bountiful-nature-production-22ec.up.railway.app"

# 크롬 확장이 이 프로그램에 연락할 때 쓰는 포트 번호.
# 확장 프로그램의 content.js 에도 같은 번호가 적혀 있어야 한다.
LOCAL_EXTENSION_PORT = 8765

# 이 PC의 신원 정보. 프로그램 시작 시 한 번만 알아내서 계속 재사용한다.
USER_NAME = getpass.getuser()    # 윈도우 로그인 계정명
PC_NAME = socket.gethostname()   # 컴퓨터 이름 (예: DESKTOP-OF0CMDB)


def get_local_ip():
    """
    이 PC의 내부 IP 주소를 알아낸다.

    관리자가 대시보드에서 "어느 PC에서 온 로그인가"를 구분할 때 쓴다.
    실패하면 "unknown"을 돌려준다. IP를 못 구했다고 프로그램을 멈출 이유는 없기 때문이다.

    [수정됨] 예전에는 `except:` 로 예외 종류를 적지 않았다.
      그러면 Ctrl+C(KeyboardInterrupt)나 시스템 종료 신호까지 삼켜버려
      프로그램을 끄려 해도 안 꺼지는 상황이 생길 수 있다.
      `except Exception:` 은 일반적인 오류만 잡고 그런 신호는 통과시킨다.
    """
    try:
        hostname = socket.gethostname()
        return socket.gethostbyname(hostname)
    except Exception:
        return "unknown"


LOCAL_IP = get_local_ip()


# 수집에서 제외할 도메인 목록.
# 수집 서버 자신을 넣어둔 이유: 로그를 보내는 행위 자체가 그 서버에 대한 접속이라
# 빼두지 않으면 '로그를 보냄 → 그 접속이 감지됨 → 또 보냄'이 끝없이 반복된다.
IGNORE_DOMAINS = {
    SERVER_DOMAIN,
}


def send_to_railway(event):
    """
    이벤트 하나를 중앙 서버로 보낸다.

    서버가 꺼져 있거나 인터넷이 끊겨도 프로그램이 죽으면 안 되므로
    오류를 잡아서 화면에 출력만 하고 넘어간다.

    ※ 전송에 실패한 로그는 사라진다. 나중에 다시 보내는 기능은 없다.
      네트워크가 불안정한 환경에서는 로그가 유실될 수 있다.
    """
    try:
        response = requests.post(
            SERVER_URL,
            json=event,
            timeout=5
        )

        if response.status_code == 200:
            print(
                f"[서버 전송 성공] "
                f"{event.get('event_type')} "
                f"{event.get('target')}"
            )
        else:
            print(
                f"[서버 오류] "
                f"{response.status_code} "
                f"{event.get('target')}"
            )

    except requests.RequestException as e:
        print(
            f"[서버 연결 실패] "
            f"{event.get('target')} "
            f"{e}"
        )


def get_domains():
    """
    현재 윈도우 DNS 캐시에 들어 있는 도메인 목록을 집합(set)으로 돌려준다.

    [DNS 캐시란]
    사이트에 접속하려면 도메인 이름(chatgpt.com)을 IP 주소로 바꿔야 하는데,
    윈도우는 한 번 바꾼 결과를 잠시 저장해둔다. 그게 DNS 캐시다.
    'ipconfig /displaydns' 명령으로 그 내용을 볼 수 있다.

    즉 이 함수는 "이 PC가 최근에 어떤 사이트를 찾아봤는가"를 알아내는 방법이다.
    브라우저를 직접 들여다보지 않고도 접속 흔적을 알 수 있어서 이 방식을 썼다.

    [한계]
      · 광고·백그라운드 통신으로 조회된 도메인도 함께 들어온다
      · 캐시에 이미 있는 사이트를 다시 열면 새 기록이 생기지 않는다
        (그래서 같은 사이트를 재방문해도 로그가 안 올라올 수 있다)

    errors="ignore" 를 준 이유:
      한국어 윈도우의 출력에 한글이 섞여 인코딩 오류가 날 수 있는데,
      우리가 필요한 것은 영문 도메인뿐이므로 깨지는 글자는 그냥 버린다.
    """
    result = subprocess.run(
        ["ipconfig", "/displaydns"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore"
    )

    domains = set()   # 집합을 쓰면 같은 도메인이 여러 번 나와도 하나만 남는다

    for line in result.stdout.splitlines():
        line = line.strip()

        # 도메인처럼 생긴 줄만 골라낸다.
        # 정규표현식 풀이: 영문/숫자/점/하이픈이 이어지다가
        #                  마지막에 점 + 영문 2글자 이상으로 끝나는 형태
        #                  (예: chatgpt.com, api.openai.com)
        match = re.match(
            r"([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$",
            line
        )

        if match:
            domain = match.group(1).lower()   # 대소문자를 소문자로 통일
            domains.add(domain)

    return domains


def should_ignore(domain):
    """이 도메인을 무시할지 판단한다. 현재는 수집 서버 자신만 제외한다."""
    return domain in IGNORE_DOMAINS


def send_web_access(domain):
    """새로 감지된 사이트 접속을 WEB_ACCESS 이벤트로 만들어 서버에 보낸다."""
    event = {
        "user": USER_NAME,
        "pc_name": PC_NAME,
        "local_ip": LOCAL_IP,
        "event_type": "WEB_ACCESS",
        "source": "windows-agent",
        "target": domain
    }

    send_to_railway(event)


class ExtensionEventHandler(BaseHTTPRequestHandler):
    """
    크롬 확장 프로그램의 연락을 받는 작은 웹 서버.

    확장 프로그램은 브라우저 안에서만 돌기 때문에 Railway 서버로 직접 보낼 수 없다.
    (사용자 이름이나 PC 이름 같은 정보도 브라우저에서는 알 수 없다)
    그래서 이 프로그램이 중간에서 받아 정보를 채워 넣고 대신 보내준다.

    127.0.0.1:8765 에서 대기하며, 이 PC 안에서만 접근할 수 있다.
    """

    def send_cors_headers(self):
        """
        CORS 허용 헤더를 붙인다.

        [CORS 란]
        브라우저는 보안상 'A 사이트에서 B 주소로 요청 보내기'를 기본적으로 막는다.
        chatgpt.com 페이지에서 127.0.0.1:8765 로 보내는 것도 여기 해당한다.
        받는 쪽이 "괜찮다"고 응답 헤더로 알려줘야 브라우저가 통과시킨다. 그 표시가 이것이다.

        ※ Allow-Origin을 "*"(전부 허용)로 열어두었다.
          로컬 전용 포트라 위험은 낮지만, 특정 확장만 허용하도록 좁히면 더 안전하다.
        """
        self.send_header(
            "Access-Control-Allow-Origin",
            "*"
        )
        self.send_header(
            "Access-Control-Allow-Headers",
            "Content-Type"
        )
        self.send_header(
            "Access-Control-Allow-Methods",
            "POST, OPTIONS"
        )

    def do_OPTIONS(self):
        """
        브라우저의 사전 확인 요청(preflight)에 응답한다.

        브라우저는 본 요청을 보내기 전에 "이 주소에 보내도 되나요?"를
        OPTIONS 방식으로 먼저 물어본다. 여기서 괜찮다고 답해줘야
        그다음에 진짜 데이터(POST)가 온다.
        """
        self.send_response(200)
        self.send_cors_headers()
        self.end_headers()

    def do_POST(self):
        """
        확장 프로그램이 보낸 파일 첨부 정보를 받아 서버로 전달한다.

        확장이 보내는 것 : 파일명, 파일 크기, 대상 사이트
        여기서 채우는 것 : 사용자 이름, PC 이름, 로컬 IP (브라우저는 알 수 없는 정보)
        """
        # 정해둔 주소가 아니면 404로 거절한다
        if self.path != "/upload-event":
            self.send_response(404)
            self.end_headers()
            return

        try:
            # 요청 본문의 길이를 헤더에서 읽는다.
            # 이 길이만큼만 읽어야 한다. 안 그러면 다음 데이터를 기다리며 멈춰버린다.
            content_length = int(
                self.headers.get(
                    "Content-Length",
                    0
                )
            )

            body = self.rfile.read(
                content_length
            )

            data = json.loads(
                body.decode("utf-8")
            )

            # 확장이 준 정보(target, file_name, file_size)에
            # 이 PC만 아는 정보(user, pc_name, local_ip)를 합쳐 완전한 이벤트를 만든다.
            #
            # ※ FILE_UPLOAD_ATTEMPT 는 '파일을 골랐다'는 뜻이지
            #   '업로드가 끝났다'는 뜻이 아니다. 파일을 고르고 취소해도 이 로그는 남는다.
            #
            # [수정됨] 예전에는 event_type 이 "FILE_UPLOAD_ATTEMPT" 로 고정돼 있었다.
            #   그래서 확장이 붙여넣기(PASTE_ATTEMPT) 같은 다른 종류를 보내도
            #   전부 파일첨부로 기록됐다. 이제 확장이 보낸 값을 그대로 쓰고,
            #   값이 없을 때만 FILE_UPLOAD_ATTEMPT 를 기본값으로 쓴다.
            event_type = data.get(
                "event_type"
            ) or "FILE_UPLOAD_ATTEMPT"

            event = {
                "user": USER_NAME,
                "pc_name": PC_NAME,
                "local_ip": LOCAL_IP,
                "event_type": event_type,
                "source": "chrome-extension",
                "target": data.get(
                    "target",
                    "unknown"
                ),
                "file_name": data.get(
                    "file_name",
                    "unknown"
                ),
                "file_size": data.get(
                    "file_size",
                    0
                )
            }

            # [추가됨] 붙여넣기 감지(PASTE_ATTEMPT)가 보내는 부가 정보를 그대로 통과시킨다.
            #   확장은 붙여넣은 '내용'을 보내지 않으므로 여기에도 내용은 없다.
            #   있는 것은 길이(text_length)와 패턴 검출 개수(pattern_hits)뿐이다.
            #   이 두 값이 없으면 대시보드가 붙여넣기 근거를 만들 수 없어 통과가 필요하다.
            if "text_length" in data:
                event["text_length"] = data.get(
                    "text_length",
                    0
                )

            if "pattern_hits" in data:
                event["pattern_hits"] = data.get(
                    "pattern_hits",
                    {}
                )

            print("")
            print(
                f"[{event_type} 감지]"
            )
            print(
                f"사이트: "
                f"{event['target']}"
            )
            print(
                f"파일명: "
                f"{event['file_name']}"
            )
            print(
                f"파일 크기: "
                f"{event['file_size']}"
            )
            print(
                f"PC: {PC_NAME}"
            )
            print(
                f"로컬 IP: {LOCAL_IP}"
            )

            send_to_railway(event)

            self.send_response(200)
            self.send_cors_headers()
            self.send_header(
                "Content-Type",
                "application/json"
            )
            self.end_headers()

            self.wfile.write(
                json.dumps(
                    {"status": "received"}
                ).encode("utf-8")
            )

        except Exception as e:

            print(
                "[확장 프로그램 이벤트 오류]",
                e
            )

            self.send_response(500)
            self.send_cors_headers()
            self.end_headers()

    def log_message(
        self,
        format,
        *args
    ):
        """
        기본 HTTP 접속 기록 출력을 끈다.

        이 함수를 비워두지 않으면 확장이 연락할 때마다
        '127.0.0.1 - - [날짜] "POST /upload-event"' 같은 줄이 화면에 계속 찍혀서,
        정작 봐야 할 감지 메시지가 묻힌다.
        """
        return


def run_extension_server():
    """확장 프로그램 대기 서버를 켜고 계속 돌린다. 별도 스레드에서 실행된다."""
    server = HTTPServer(
        ("127.0.0.1", LOCAL_EXTENSION_PORT),
        ExtensionEventHandler
    )

    print(
        f"Chrome 확장 연결 대기: "
        f"http://127.0.0.1:"
        f"{LOCAL_EXTENSION_PORT}"
    )

    server.serve_forever()


# ============================================================================
# 여기서부터 프로그램이 실제로 시작된다
# ============================================================================

# 확장 대기 서버를 별도 스레드로 띄운다.
# daemon=True 는 "메인 흐름이 끝나면 이 스레드도 같이 종료하라"는 뜻이다.
# 이게 없으면 Ctrl+C 를 눌러도 프로그램이 안 꺼진다.
extension_thread = threading.Thread(
    target=run_extension_server,
    daemon=True
)

extension_thread.start()


# 시작 시점의 DNS 캐시를 '이미 알고 있는 것'으로 기록해둔다.
# ★ 이 때문에 프로그램을 켜기 전에 방문했던 사이트는 로그로 올라오지 않는다.
#   시연할 때 "사이트를 열었는데 로그가 안 뜬다"면 대개 이 이유다.
#   Agent를 먼저 켠 다음 사이트를 열어야 한다.
known_domains = get_domains()

print("")
print("NexusGuard Agent 시작")
print(f"사용자: {USER_NAME}")
print(f"PC 이름: {PC_NAME}")
print(f"로컬 IP: {LOCAL_IP}")
print("새로운 사이트 접속 감시 중...")
print("")


# ── 메인 감시 루프 ──────────────────────────────────────────
# 1초마다 DNS 캐시를 다시 읽고, 지난번에 없던 도메인만 골라 서버로 보낸다.
# 이 창을 닫으면 감시가 멈추므로 수집하는 동안은 열어두어야 한다.
while True:

    current_domains = get_domains()

    # 집합끼리 빼기: 지금 목록에서 이미 알던 것을 제외하면 '새로 생긴 것'만 남는다.
    # 예) {a, b, c} - {a, b} = {c}
    new_domains = (
        current_domains
        - known_domains
    )

    for domain in sorted(
        new_domains
    ):

        if should_ignore(domain):
            continue    # 제외 목록에 있으면 건너뛴다

        print(
            f"[새 사이트 감지] "
            f"{domain}"
        )

        send_web_access(domain)

    # 이번에 본 목록을 '이미 아는 것'으로 갱신한다.
    # 이렇게 해야 같은 도메인을 매초 반복해서 보내지 않는다.
    known_domains = current_domains

    time.sleep(1)   # 1초 쉬었다가 다시 확인. 안 쉬면 CPU를 계속 잡아먹는다