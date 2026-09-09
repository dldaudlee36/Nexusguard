import os
import subprocess
import time
import re
import requests
import socket
import getpass
import threading
import json

from http.server import BaseHTTPRequestHandler, HTTPServer


SERVER_URL = "https://bountiful-nature-production-22ec.up.railway.app/events"
SERVER_DOMAIN = "bountiful-nature-production-22ec.up.railway.app"

LOCAL_EXTENSION_PORT = 8765

USER_NAME = getpass.getuser()
PC_NAME = socket.gethostname()


def get_local_ip():
    try:
        hostname = socket.gethostname()
        return socket.gethostbyname(hostname)
    except:
        return "unknown"


LOCAL_IP = get_local_ip()


IGNORE_DOMAINS = {
    SERVER_DOMAIN,
}

# ---------------------------------------------------------------------------
# P1: 로컬 오프라인 버퍼 (Queue) — Railway 단절 대비
# 전송 실패 시 JSONL 파일에 이벤트를 저장하고, 복구 후 재전송한다.
# ---------------------------------------------------------------------------
_QUEUE_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data")
_QUEUE_FILE = os.path.join(_QUEUE_DIR, "agent_queue.jsonl")
_MAX_QUEUE_SIZE = 500   # 최대 큐 보관 건수 (초과 시 oldest 자동 삭제)


def _ensure_queue_dir():
    """큐 저장 디렉터리가 없으면 생성"""
    try:
        os.makedirs(_QUEUE_DIR, exist_ok=True)
    except Exception:
        pass


def _enqueue(event: dict):
    """전송 실패 이벤트를 로컬 JSONL 큐에 추가"""
    _ensure_queue_dir()
    try:
        # 큐 크기 제한 검사
        existing = _read_queue()
        if len(existing) >= _MAX_QUEUE_SIZE:
            # 가장 오래된 이벤트 제거 (FIFO)
            existing = existing[-(  _MAX_QUEUE_SIZE - 1):]
            _write_queue(existing)

        with open(_QUEUE_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
        print(f"[큐 저장] 전송 실패 이벤트 로컬 버퍼 저장 완료 ({event.get('event_type', '?')})")
    except Exception as e:
        print(f"[큐 저장 오류] {e}")


def _read_queue() -> list:
    """로컬 큐에서 이벤트 목록 읽기"""
    if not os.path.exists(_QUEUE_FILE):
        return []
    events = []
    try:
        with open(_QUEUE_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except Exception:
                        pass
    except Exception:
        pass
    return events


def _write_queue(events: list):
    """큐 파일 전체 덮어쓰기"""
    _ensure_queue_dir()
    try:
        with open(_QUEUE_FILE, "w", encoding="utf-8") as f:
            for ev in events:
                f.write(json.dumps(ev, ensure_ascii=False) + "\n")
    except Exception as e:
        print(f"[큐 쓰기 오류] {e}")


def flush_queue():
    """
    로컬 큐에 쌓인 이벤트를 Railway 서버로 일괄 재전송.
    성공한 이벤트는 큐에서 제거, 실패한 이벤트는 다음 사이클로 유지.
    """
    queued = _read_queue()
    if not queued:
        return

    remaining = []
    success_count = 0
    for event in queued:
        try:
            response = requests.post(SERVER_URL, json=event, timeout=5)
            if response.status_code == 200:
                success_count += 1
            else:
                remaining.append(event)
        except requests.RequestException:
            remaining.append(event)

    _write_queue(remaining)
    if success_count > 0:
        print(f"[큐 플러시] {success_count}건 재전송 성공 / 잔여 {len(remaining)}건")


def send_to_railway(event):
    """
    Railway 중앙 서버로 이벤트 전송.
    전송 실패 시 로컬 오프라인 큐에 저장하여 나중에 재시도.
    """
    # 매 전송 전 큐에 쌓인 이전 실패 이벤트 재전송 시도
    flush_queue()

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
            # 서버 오류(4xx/5xx) 시 큐에 저장
            _enqueue(event)

    except requests.RequestException as e:
        print(
            f"[서버 연결 실패] "
            f"{event.get('target')} "
            f"{e}"
        )
        # 네트워크 오류 시 큐에 저장
        _enqueue(event)




def get_domains():
    result = subprocess.run(
        ["ipconfig", "/displaydns"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore"
    )

    domains = set()

    for line in result.stdout.splitlines():
        line = line.strip()

        match = re.match(
            r"([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$",
            line
        )

        if match:
            domain = match.group(1).lower()
            domains.add(domain)

    return domains


def should_ignore(domain):
    return domain in IGNORE_DOMAINS


def send_web_access(domain):

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

    def send_cors_headers(self):
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
        self.send_response(200)
        self.send_cors_headers()
        self.end_headers()

    def do_POST(self):

        if self.path != "/upload-event":
            self.send_response(404)
            self.end_headers()
            return

        try:
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

            event = {
                "user": USER_NAME,
                "pc_name": PC_NAME,
                "local_ip": LOCAL_IP,
                "event_type": "FILE_UPLOAD_ATTEMPT",
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

            print("")
            print(
                "[파일 업로드 시도 감지]"
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
        return


def run_extension_server():

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


extension_thread = threading.Thread(
    target=run_extension_server,
    daemon=True
)

extension_thread.start()


known_domains = get_domains()

print("")
print("NexusGuard Agent 시작")
print(f"사용자: {USER_NAME}")
print(f"PC 이름: {PC_NAME}")
print(f"로컬 IP: {LOCAL_IP}")
print("새로운 사이트 접속 감시 중...")
print("")


while True:

    current_domains = get_domains()

    new_domains = (
        current_domains
        - known_domains
    )

    for domain in sorted(
        new_domains
    ):

        if should_ignore(domain):
            continue

        print(
            f"[새 사이트 감지] "
            f"{domain}"
        )

        send_web_access(domain)

    known_domains = current_domains

    time.sleep(1)