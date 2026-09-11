"""NexusGuard Agent v3: DNS, file-selection and paste metadata collection."""
import getpass
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
import requests

VERSION = '3.0.0'
SERVER_URL = os.getenv('RAILWAY_URL', 'https://bountiful-nature-production-22ec.up.railway.app/events')
SERVER_DOMAIN = urlsplit(SERVER_URL).hostname
LOCAL_EXTENSION_PORT = int(os.getenv('NEXUSGUARD_EXTENSION_PORT', '8765'))
USER_NAME = getpass.getuser()
PC_NAME = socket.gethostname()

def get_local_ip():
    try:
        value = socket.gethostbyname(socket.gethostname())
        if not ipaddress.ip_address(value).is_loopback:
            return value
    except (OSError, ValueError):
        pass
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect((SERVER_DOMAIN, 443))
            return probe.getsockname()[0]
    except OSError:
        return 'unknown'

def base_event(kind, target):
    return {'user':USER_NAME, 'pc_name':PC_NAME, 'local_ip':get_local_ip(),
            'event_type':kind, 'target':target, 'agent_version':VERSION}

def extension_event(path, data):
    if not isinstance(data, dict):
        raise ValueError('JSON object required')
    target = data.get('target')
    if not isinstance(target, str) or not target.strip() or len(target)>253:
        raise ValueError('Valid site hostname required')
    kind = 'PASTE_ATTEMPT' if path == '/paste-event' else 'FILE_UPLOAD_ATTEMPT'
    result = base_event(kind, target)
    result['source'] = 'chrome-extension'
    if kind == 'PASTE_ATTEMPT':
        length = data.get('text_length')
        if type(length) is not int or not 0 < length <= 100_000_000:
            raise ValueError('text_length must be a positive integer')
        result['text_length'] = length
    else:
        name, size = data.get('file_name'), data.get('file_size')
        if not isinstance(name, str) or len(name)>1024:
            raise ValueError('Valid file name required')
        if type(size) is not int or size<0:
            raise ValueError('Valid file size required')
        result.update(file_name=name, file_size=size)
    stamp = data.get('timestamp')
    if stamp is not None:
        if not isinstance(stamp,str) or len(stamp)>64:
            raise ValueError('Valid timestamp required')
        parsed = datetime.fromisoformat(stamp.replace('Z','+00:00'))
        if parsed.tzinfo is None:
            raise ValueError('Timestamp must include timezone')
        result['client_event_time'] = parsed.astimezone(timezone.utc).isoformat()
    # Whitelist only metadata above. Pasted text/HTML is never forwarded.
    return result

def send_to_railway(event):
    try:
        response = requests.post(SERVER_URL, json=event, timeout=8)
        response.raise_for_status()
        print(f"[서버 전송 성공] {event['event_type']} {event['target']}", flush=True)
        return True
    except requests.RequestException as error:
        print(f"[서버 전송 실패] {type(error).__name__} {event['event_type']}", flush=True)
        return False

class ExtensionEventHandler(BaseHTTPRequestHandler):
    def respond(self, code, data):
        body = json.dumps(data).encode('utf-8')
        self.send_response(code)
        self.send_header('Access-Control-Allow-Origin','*')
        self.send_header('Access-Control-Allow-Headers','Content-Type')
        self.send_header('Access-Control-Allow-Methods','GET, POST, OPTIONS')
        self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.respond(200,{})

    def do_GET(self):
        if self.path == '/health':
            self.respond(200,{'service':'NexusGuardAgent','version':VERSION})
        else:
            self.respond(404,{'error':'Not found'})

    def do_POST(self):
        if self.path not in ('/upload-event','/paste-event'):
            self.respond(404,{'error':'Not found'})
            return
        try:
            count = int(self.headers.get('Content-Length','0'))
            if not 0 < count <= 16384:
                self.respond(413,{'error':'Metadata payload too large or empty'})
                return
            data = json.loads(self.rfile.read(count).decode('utf-8'))
            event = extension_event(self.path, data)
        except (ValueError, UnicodeError):
            self.respond(400,{'error':'Invalid event metadata'})
            return
        success = send_to_railway(event)
        if success:
            self.respond(200,{'status':'saved', 'event_type':event['event_type']})
        else:
            self.respond(502,{'error':'Railway delivery failed'})

    def log_message(self,*args):
        pass

def get_domains():
    result = subprocess.run(['ipconfig','/displaydns'],capture_output=True,text=True,
                            encoding='utf-8',errors='ignore',creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    return {line.strip().lower() for line in result.stdout.splitlines()
            if re.fullmatch(r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',line.strip())}

def main():
    if hasattr(sys.stdout,'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    try:
        server = ThreadingHTTPServer(('127.0.0.1',LOCAL_EXTENSION_PORT),ExtensionEventHandler)
    except OSError:
        print(f'포트 {LOCAL_EXTENSION_PORT} 사용 중: 기존 Agent 또는 테스트 서버를 종료하세요.',flush=True)
        return 1
    threading.Thread(target=server.serve_forever,daemon=True).start()
    print(f'NexusGuard Agent {VERSION}\nPC: {PC_NAME}\n로컬 IP: {get_local_ip()}\n확장 연결: 127.0.0.1:{LOCAL_EXTENSION_PORT}',flush=True)
    known = get_domains()
    try:
        while True:
            current = get_domains()
            for domain in sorted(current-known):
                if domain != SERVER_DOMAIN:
                    event = base_event('WEB_ACCESS',domain)
                    event['source']='windows-agent'
                    send_to_railway(event)
            known=current
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
