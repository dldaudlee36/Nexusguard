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


def send_to_railway(event):
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