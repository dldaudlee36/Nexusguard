"""
NexusGuard 중앙 수집 서버 (Railway 배포본 소스 사본)

=====================================================================
[이 서버가 하는 일]
=====================================================================
여러 팀원 PC의 Agent가 보내는 로그를 한곳에 모아 데이터베이스에 저장하고,
대시보드가 요청하면 꺼내주는 창고 역할을 한다.

  [팀원A PC Agent] ─┐
  [팀원B PC Agent] ─┼─ POST /events ─▶ 이 서버 ─▶ PostgreSQL
  [팀원C PC Agent] ─┘                     │
                                          └─ GET /events ─▶ [대시보드]

이 서버는 판정을 하지 않는다. 받아서 저장하고 돌려주기만 한다.
위험도 판정은 대시보드 쪽 엔진(engine/correlation.py)이 담당한다.

[제공하는 주소 4개]
  GET  /        서버가 살아 있는지 확인 (헬스체크)
  POST /events  Agent가 로그를 보내는 곳          — 인증 없음
  GET  /events  대시보드가 로그를 가져가는 곳     — API 키 필요, 최신 100건
  GET  /logs    브라우저로 로그를 바로 보는 화면  — 인증 없음

[⚠ 보안상 확인이 필요한 부분]
  1) POST /events 에 인증이 없다.
     주소만 알면 누구나 가짜 로그를 밀어 넣을 수 있다.

  2) GET /logs 에도 인증이 없다.
     주소를 아는 사람은 누구나 전체 수집 로그를 열람할 수 있다.
     GET /events 는 API 키로 막아두었는데 /logs 는 뚫려 있어 앞뒤가 맞지 않는다.

  3) API_KEY 기본값이 코드에 그대로 적혀 있다.
     환경변수가 설정되지 않으면 이 값이 그대로 쓰인다.
"""

import os
import json                   # [추가됨] raw_data 를 제대로 된 JSON 문자열로 저장하기 위해

from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS

import psycopg2              # PostgreSQL 접속 라이브러리
import psycopg2.extras       # 조회 결과를 딕셔너리로 받기 위한 도구


app = Flask(__name__)
CORS(app)   # 다른 주소(대시보드)에서 이 서버를 호출할 수 있게 허용


# DB 접속 주소. Railway가 환경변수로 자동 넣어준다.
DATABASE_URL = os.environ.get("DATABASE_URL")

# 대시보드 인증용 키.
# ⚠ 환경변수가 없으면 뒤의 기본값이 그대로 쓰인다. 소스에 키가 남아 있는 상태다.
API_KEY = os.environ.get("API_KEY", "20110313")


def get_db_connection():
    """
    DB 연결을 새로 만들어 돌려준다.

    ※ 요청마다 새 연결을 맺고 끊는 방식이다.
      요청이 많아지면 연결 비용이 부담이 되므로,
      실제 운영에서는 커넥션 풀(연결을 미리 만들어두고 돌려쓰는 방식)을 쓴다.
    """
    return psycopg2.connect(DATABASE_URL)


def save_event(
    user_name,
    pc_name,
    local_ip,
    event_type,
    source,
    target,
    raw_data=""
):
    """
    로그 한 건을 events 테이블에 저장한다.

    SQL에 값을 %s 자리표시자로 넘기는 것이 중요하다.
    문자열을 직접 이어붙이면 SQL 인젝션 공격에 뚫린다.
    이렇게 넘기면 라이브러리가 알아서 안전하게 처리해준다.
    """
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        """
        INSERT INTO events
        (
            user_name,
            pc_name,
            local_ip,
            event_type,
            source,
            target,
            raw_data
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """,
        (
            user_name,
            pc_name,
            local_ip,
            event_type,
            source,
            target,
            raw_data
        )
    )

    conn.commit()   # commit 을 해야 실제로 DB에 반영된다
    cur.close()
    conn.close()


@app.route("/")
def home():
    """서버가 살아 있는지 확인하는 용도. 브라우저로 열면 이 문구가 보인다."""
    return "NexusGuard API Running"


@app.route("/events", methods=["POST"])
def receive_event():
    """
    Agent가 보낸 로그를 받아 DB에 저장한다.

    ⚠ 인증 검사가 없다. 이 주소를 아는 누구나 로그를 넣을 수 있다.
      Agent에도 키를 넣고 여기서 확인하는 방식이 필요하다.
    """
    # silent=True 는 JSON 형식이 아니어도 예외를 내지 말라는 뜻이다.
    # 대신 None이 돌아오므로 바로 아래에서 확인한다.
    data = request.get_json(silent=True)

    if not data:
        return jsonify({
            "error": "JSON data required"
        }), 400

    # 필요한 항목을 꺼낸다. 빠진 항목이 있어도 "unknown"으로 채워 저장은 되게 한다.
    # 로그 하나를 통째로 버리는 것보다 일부라도 남기는 편이 낫다는 판단이다.
    user_name = data.get("user", "unknown")
    pc_name = data.get("pc_name", "unknown")
    local_ip = data.get("local_ip", "unknown")
    event_type = data.get("event_type", "unknown")
    source = data.get("source", "unknown")
    target = data.get("target", "unknown")

    # 원본 전체를 문자열로 만들어 함께 저장한다.
    # 위에서 꺼내지 않은 항목(file_name, file_size 등)도 여기 남아 있어서
    # 나중에 대시보드가 다시 꺼내 쓸 수 있다.
    #
    # [수정됨] 예전에는 str(data) 였다.
    #   str(data) 는 JSON이 아니라 파이썬 표현식 문자열을 만든다.
    #   {'user': 'kim'} 처럼 작은따옴표가 되어 json.loads() 로는 못 읽고,
    #   그래서 대시보드 쪽(team_collector._parse_raw_data)이
    #   ast.literal_eval 로 우회 처리하고 있었다.
    #   json.dumps 로 제대로 된 JSON을 저장하면 그 우회가 필요 없다.
    #   ensure_ascii=False 는 한글이 \uXXXX 로 깨지지 않게 하기 위함이다.
    raw_data = json.dumps(data, ensure_ascii=False)

    try:
        save_event(
            user_name=user_name,
            pc_name=pc_name,
            local_ip=local_ip,
            event_type=event_type,
            source=source,
            target=target,
            raw_data=raw_data
        )

        return jsonify({
            "status": "saved",
            "user": user_name,
            "pc_name": pc_name,
            "local_ip": local_ip,
            "event_type": event_type,
            "target": target
        }), 200

    except Exception as e:
        print("DB 저장 오류:", e)

        return jsonify({
            "error": str(e)
        }), 500


@app.route("/events", methods=["GET"])
def get_events():
    """
    대시보드가 로그를 가져가는 주소. 최신 100건을 JSON으로 돌려준다.

    ★ 여기만 API 키 검사가 있다. (아래 /logs 에는 없다)

    ※ 항상 최신 100건만 준다. 그보다 오래된 로그는 대시보드에서 볼 수 없다.
      로그가 몰리는 시간대에는 100건이 금방 밀려 유실될 수 있으므로,
      '마지막으로 받은 ID 이후만 주세요' 같은 방식이 더 안전하다.
    """
    # 요청 헤더에서 키를 꺼내 비교한다
    api_key = request.headers.get("X-API-Key")

    if api_key != API_KEY:
        return jsonify({
            "error": "Unauthorized"
        }), 401   # 401 = 인증 실패

    try:
        conn = get_db_connection()

        # RealDictCursor 를 쓰면 조회 결과가 딕셔너리로 나온다.
        # row[0] 대신 row["user_name"] 처럼 쓸 수 있어 JSON으로 바로 바꾸기 편하다.
        cur = conn.cursor(
            cursor_factory=psycopg2.extras.RealDictCursor
        )

        cur.execute(
            """
            SELECT
                id,
                event_time,
                user_name,
                pc_name,
                local_ip,
                event_type,
                source,
                target,
                risk_score,
                raw_data
            FROM events
            ORDER BY id DESC
            LIMIT 100
            """
        )

        rows = cur.fetchall()

        cur.close()
        conn.close()

        return jsonify(rows)

    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500


@app.route("/logs")
def logs_page():
    """
    수집된 로그를 브라우저에서 표로 바로 볼 수 있는 간이 화면.
    대시보드를 켜지 않고 "로그가 들어오고 있나?"만 빠르게 확인할 때 쓴다.

    ⚠ 인증이 없다. 주소를 아는 사람은 누구나 전체 로그를 볼 수 있다.
      바로 위 GET /events 는 API 키로 막았는데 여기는 뚫려 있어 일관성이 없다.
      같은 키 검사를 붙이는 것이 맞다.
    """
    try:
        conn = get_db_connection()

        cur = conn.cursor(
            cursor_factory=psycopg2.extras.RealDictCursor
        )

        cur.execute(
            """
            SELECT
                event_time,
                user_name,
                pc_name,
                local_ip,
                event_type,
                source,
                target,
                risk_score,
                raw_data
            FROM events
            ORDER BY id DESC
            LIMIT 100
            """
        )

        rows = cur.fetchall()

        cur.close()
        conn.close()

        # HTML을 문자열로 직접 작성한다.
        # {% for row in rows %} 부분은 Jinja2 템플릿 문법으로,
        # 로그 개수만큼 표의 행을 반복해서 그려준다.
        # Jinja2는 값을 자동으로 escape 하므로 로그 내용에 태그가 섞여 있어도 안전하다.
        html = """
        <!DOCTYPE html>
        <html lang="ko">
        <head>
            <meta charset="UTF-8">
            <title>NexusGuard Logs</title>

            <style>
                body {
                    font-family: Arial, sans-serif;
                    margin: 30px;
                }

                table {
                    border-collapse: collapse;
                    width: 100%;
                }

                th,
                td {
                    border: 1px solid #cccccc;
                    padding: 8px;
                    text-align: left;
                    vertical-align: top;
                }

                th {
                    background-color: #f2f2f2;
                }
            </style>
        </head>

        <body>

            <h1>NexusGuard Logs</h1>

            <table>

                <tr>
                    <th>시간</th>
                    <th>사용자</th>
                    <th>PC</th>
                    <th>로컬 IP</th>
                    <th>이벤트</th>
                    <th>소스</th>
                    <th>사이트</th>
                    <th>위험점수</th>
                    <th>원본 데이터</th>
                </tr>

                {% for row in rows %}

                <tr>
                    <td>{{ row.event_time }}</td>
                    <td>{{ row.user_name }}</td>
                    <td>{{ row.pc_name }}</td>
                    <td>{{ row.local_ip }}</td>
                    <td>{{ row.event_type }}</td>
                    <td>{{ row.source }}</td>
                    <td>{{ row.target }}</td>
                    <td>{{ row.risk_score }}</td>
                    <td>{{ row.raw_data }}</td>
                </tr>

                {% endfor %}

            </table>

        </body>
        </html>
        """

        return render_template_string(
            html,
            rows=rows
        )

    except Exception as e:
        return f"DB 오류: {e}", 500


if __name__ == "__main__":
    # Railway 같은 클라우드는 실행할 포트를 환경변수 PORT로 지정해준다.
    # 로컬에서 직접 돌릴 때는 그 값이 없으므로 8080을 쓴다.
    port = int(
        os.environ.get(
            "PORT",
            8080
        )
    )

    # host="0.0.0.0" 은 "이 컴퓨터의 모든 네트워크에서 접속을 받겠다"는 뜻이다.
    # 기본값(127.0.0.1)이면 서버 자기 자신에서만 접근되어 외부 Agent가 붙을 수 없다.
    app.run(
        host="0.0.0.0",
        port=port
    )