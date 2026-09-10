"""
NexusGuard - Shadow IT & AI Governance Engine
DNS 질의 기반 섀도우 IT/AI 식별, 위험도 산출 및 양성화 워크플로 관리 모듈

=====================================================================
[이 파일이 하는 일]
=====================================================================
correlation.py 가 '위험한 사람'을 찾는다면,
이 파일은 '위험한 서비스'를 찾는다.

직원들이 접속한 외부 사이트를 하나씩 자산으로 등록하고,
각 서비스가 얼마나 위험한지 판정해 관리자에게 보여준다.

[핵심 철학 — 왜 무조건 막지 않는가]
보안팀이 모든 AI 사이트를 막아버리면 직원들은 스마트폰 테더링이나
개인 노트북으로 몰래 쓴다. 이걸 '풍선 효과'라고 한다.
막을수록 회사가 통제할 수 없는 곳으로 옮겨갈 뿐이다.

그래서 NexusGuard는 관리자에게 3가지 선택지를 준다.
  ① 정식 승인(양성화) — 업무에 꼭 필요하면 기업용 계약을 맺고 열어준다
  ② 사내 대체재 안내 — "그거 대신 사내 AI 쓰세요"라고 알려준다
  ③ 차단             — 정말 위험한 것만 막는다

[위험도를 판정하는 3단계 (아래로 갈수록 나중에 시도)]
  1) KNOWN_SAAS_DATABASE  — 미리 조사해둔 목록에 있으면 그 값을 쓴다 (가장 정확, 즉시)
  2) Gemini LLM 분석      — 목록에 없으면 AI에게 물어본다 (신규 사이트 대응)
  3) 휴리스틱 폴백        — LLM도 못 쓰면 도메인 이름으로 대충 판단한다 (최후의 수단)

3단계로 만든 이유: 외부 AI 사이트는 매일 수십 개씩 새로 생긴다.
목록만으로는 절대 못 따라가고, 그렇다고 LLM만 믿으면 키가 없거나
네트워크가 끊겼을 때 아무것도 못 하게 된다.

[실시간 수집 연동]
sync_railway_events() 가 Railway에서 모은 실제 접속 로그를 받아
각 자산의 접속 건수·사용자 목록·사용 빈도를 갱신하고,
처음 보는 외부 AI/SaaS 도메인을 자산 목록에 자동으로 추가한다.
이 집계 결과는 analyze_domain_with_gemini() 의 live_context 로도 넘어가서,
LLM이 "이 회사에서 몇 명이 몇 번 썼는지"까지 알고 진단하게 한다.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime
from nexusguard.schemas.event import SecurityEvent, LogSource
from nexusguard.schemas.incident import ShadowAIAsset, Severity, SanctionStatus


# 사내 정적 SaaS & AI 지식 베이스
# 자주 나오는 서비스를 미리 조사해서 넣어둔 목록이다. LLM 호출 없이 즉시 판정할 수 있다.
#   default_status : 기본 승인 상태 (APPROVED 승인 / UNAPPROVED 미승인 / BLOCKED 차단)
#   default_risk   : 기본 위험 등급
#   ai_diagnosis   : 왜 그 등급인지에 대한 설명 (관리자가 읽는다)
#   alternative    : 대신 쓸 수 있는 사내 도구
KNOWN_SAAS_DATABASE = {
    "slack.com": {
        "service_name": "Slack",
        "category": "사내 협업 도구",
        "default_status": SanctionStatus.APPROVED,
        "default_risk": Severity.LOW,
        "ai_diagnosis": "사내 정식 계약 체결 도구 (SSO 연동 및 데이터 보존 정책 적용됨)",
        "alternative": None
    },
    "chatgpt.com": {
        "service_name": "ChatGPT",
        "category": "대화형 생성형 AI",
        "default_status": SanctionStatus.UNAPPROVED,
        "default_risk": Severity.HIGH,
        "ai_diagnosis": "사용자 입력 데이터가 AI 모델 재학습에 활용될 수 있어 사내 기밀 유출 고위험",
        "alternative": "사내 프라이빗 AI 포털 (Aegis-GenAI)"
    },
    "api.openai.com": {
        "service_name": "OpenAI API",
        "category": "생성형 AI API",
        "default_status": SanctionStatus.UNAPPROVED,
        "default_risk": Severity.HIGH,
        "ai_diagnosis": "프로그램 코드를 통한 대량 사내 데이터 전송 가능성",
        "alternative": "사내 인가 AI Gateway"
    },
    "dropbox.com": {
        "service_name": "Dropbox",
        "category": "클라우드 파일 공유",
        "default_status": SanctionStatus.UNAPPROVED,
        "default_risk": Severity.MEDIUM,
        "ai_diagnosis": "개인 계정 사용 추정. 외부 협업 시 링크 유출에 따른 무단 다운로드 위험",
        "alternative": "사내 보안 파일 공유기 (SecureDrive)"
    },
    "notion.so": {
        "service_name": "Notion",
        "category": "문서 및 지식 관리",
        "default_status": SanctionStatus.UNAPPROVED,
        "default_risk": Severity.LOW,
        "ai_diagnosis": "단순 문서 작성 용도 관찰 중. 현재까지 대용량 파일 전송 미탐지",
        "alternative": "사내 Confluence"
    },
    "wetransfer.com": {
        "service_name": "WeTransfer",
        "category": "대용량 일회성 전송",
        "default_status": SanctionStatus.BLOCKED,
        "default_risk": Severity.HIGH,
        "ai_diagnosis": "익명 파일 전송 서비스로 사내 감사 로그 추적 불가 및 데이터 유출 취약",
        "alternative": "보안 대용량 메일 발송 시스템"
    },
    "claude.ai": {
        "service_name": "Claude AI",
        "category": "대화형 생성형 AI",
        "default_status": SanctionStatus.UNAPPROVED,
        "default_risk": Severity.HIGH,
        "ai_diagnosis": "긴 문서 분석 기능으로 인해 대량 사내 보고서 업로드 위험 존재",
        "alternative": "사내 프라이빗 AI 포털"
    }
}


def analyze_domain_with_gemini(domain: str, api_key: Optional[str] = None, live_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Google Gemini API(google-genai)를 활용하여 미등록 도메인의 용도, 재학습 위험도, 보안 소견을 실시간 분석.
    Railway 실시간 수집 로그 정보(접속 횟수, 임직원, IP)를 프롬프트에 반영.
    API 키가 없거나 실패 시 지능형 휴리스틱 룰베이스로 안전하게 폴백.

    live_context: sync_railway_events() 가 집계한 실제 수집 통계.
                  {"count": 접속 횟수, "users": 사용자 집합, "ips": IP 집합} 형태다.
                  이 값을 프롬프트에 넣으면 LLM이 "사내에서 실제로 얼마나 쓰이는지"까지
                  감안해 진단하므로, 도메인 이름만 보고 판단할 때보다 소견이 구체적이다.
                  없으면(None) 도메인 이름만으로 분석한다.

    [폴백(fallback)이란]
    "실패하면 대신 이걸 쓴다"는 뜻이다.
    이 함수는 어떤 경우에도 예외를 밖으로 던지지 않고 항상 결과를 돌려준다.
    LLM이 안 되더라도 대시보드가 멈추면 안 되기 때문이다.

    폴백이 일어나는 경우:
      · API 키가 없을 때
      · 모델 3개를 다 시도했는데 전부 실패했을 때
      · 응답이 왔는데 JSON 형식이 아닐 때
      · 그 외 알 수 없는 오류
    """
    import os
    import json

    # 키는 인자로 직접 받거나, 없으면 환경변수에서 읽는다.
    # 코드에 키를 적어두지 않기 위한 구조다.
    key = api_key or os.environ.get("GEMINI_API_KEY")
    if not key:
        return _fallback_heuristic_analysis(domain)

    try:
        from google import genai
        client = genai.Client(api_key=key)

        context_info = ""
        if live_context:
            context_info = f"""
사내 실제 수집 트래픽 현황 (Railway 에이전트 연동):
- 누적 접속 횟수: {live_context.get('count', 1)}건
- 접속 임직원: {', '.join(live_context.get('users', ['사내 단말']))}
- 접속 단말 IP: {', '.join(live_context.get('ips', ['unknown']))}
"""

        prompt = f"""
당신은 엔터프라이즈 보안관제 및 Shadow AI 거버넌스 전문가입니다.
사내 직원의 단말(Railway Agent)에서 수집된 아래 외부 도메인을 분석하여 보안 평가 결과를 JSON으로 응답하세요.

대상 도메인: {domain}
{context_info}

반드시 아래 JSON 형식만 반환하세요:
{{
    "service_name": "서비스명 (예: Perplexity AI)",
    "category": "서비스 카테고리 (예: 검색형 생성형 AI / 클라우드 파일 공유 / 외부 SaaS 등)",
    "risk_level": "HIGH / MEDIUM / LOW 중 하나",
    "ai_diagnosis": "보안 진단 소견 (1~2문장, 사용자 프롬프트 데이터의 외부 모델 재학습 여부 및 기밀 유출 위험성 평가)"
}}
"""
        models_to_try = ["gemini-3.6-flash", "gemini-2.5-flash", "gemini-1.5-flash"]
        response = None
        for m in models_to_try:
            try:
                response = client.models.generate_content(
                    model=m,
                    contents=prompt,
                )
                if response and response.text:
                    break   # 응답을 받았으면 더 시도하지 않는다
            except Exception:
                continue    # 이 모델은 안 되니 다음 모델로

        # 세 모델 모두 실패 → 휴리스틱으로 넘어간다
        if not response or not response.text:
            return _fallback_heuristic_analysis(domain)

        # LLM은 종종 JSON을 ```json ... ``` 코드블록으로 감싸서 돌려준다.
        # 그대로 json.loads()에 넣으면 오류가 나므로 감싼 부분을 벗겨낸다.
        text = response.text.strip()
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0].strip()
        elif "```" in text:
            text = text.split("```")[1].split("```")[0].strip()
        data = json.loads(text)

        # LLM이 준 문자열("HIGH")을 프로그램이 쓰는 Severity 값으로 바꾼다
        r_level = data.get("risk_level", "MEDIUM").upper()
        severity_map = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}
        return {
            "service_name": data.get("service_name", domain.capitalize()),
            "category": data.get("category", "외부 AI/SaaS 서비스"),
            "risk_level": severity_map.get(r_level, Severity.MEDIUM),
            "ai_diagnosis": data.get("ai_diagnosis", "Gemini AI 분석 완료: 사내 데이터 보안 정책 준수 필요"),
            "alternative": None
        }
    except Exception:
        # 어떤 오류가 나든 대시보드는 멈추면 안 된다. 조용히 휴리스틱으로 대체한다.
        return _fallback_heuristic_analysis(domain)


def _fallback_heuristic_analysis(domain: str) -> Dict[str, Any]:
    """
    LLM을 쓸 수 없을 때 도메인 이름만 보고 대략 판정하는 함수.

    '휴리스틱(heuristic)'은 정확하진 않지만 대체로 맞는 간단한 규칙을 말한다.
    여기서는 도메인 이름에 어떤 단어가 들어 있는지만 본다.

      'ai', 'gpt', 'claude' 등이 있으면  → 생성형 AI 로 보고 HIGH
      'drive', 'cloud', 'share' 등이면   → 클라우드 서비스로 보고 MEDIUM
      둘 다 아니면                        → 일반 사이트로 보고 LOW

    당연히 틀릴 수 있다. (예: 'thai-food.com'에도 'ai'가 들어 있다)
    어디까지나 LLM이 안 될 때 쓰는 최소한의 안전장치다.
    """
    d = domain.lower()

    # 1) 생성형 AI 계열로 보이는 경우 → 위험도 HIGH
    if any(k in d for k in ["ai", "gpt", "bot", "deep", "claude", "gemini", "copilot", "llm", "perplexity", "sora", "midjourney", "hugging"]):
        return {
            "service_name": domain.capitalize(),
            "category": "생성형 AI 및 LLM 서비스",
            "risk_level": Severity.HIGH,
            "ai_diagnosis": "미등록 생성형 AI 서비스: 프롬프트 입력 데이터의 외부 모델 재학습 및 기밀 유출 고위험",
            "alternative": None
        }
    # 2) 클라우드 저장소·파일 전송 계열 → 위험도 MEDIUM
    elif any(k in d for k in ["drive", "box", "cloud", "share", "transfer", "sync", "mega", "storage", "datadog", "kakao"]):
        return {
            "service_name": domain.capitalize(),
            "category": "클라우드 서비스 및 데이터 전송",
            "risk_level": Severity.MEDIUM,
            "ai_diagnosis": "외부 클라우드 서비스 연동 확인. 대용량 데이터 반출 및 비인가 접근 여부 모니터링 필요",
            "alternative": None
        }
    # 3) 그 외 일반 사이트 → 위험도 LOW
    else:
        return {
            "service_name": domain.capitalize(),
            "category": "일반 외부 웹/SaaS 서비스",
            "risk_level": Severity.LOW,
            "ai_diagnosis": "정상 웹 트래픽 관찰 중. 현재까지 민감 데이터 대량 전송 징후 없음",
            "alternative": None
        }


class ShadowAIGovernanceEngine:
    """
    섀도우 IT 및 생성형 AI 거버넌스 분석기

    사내에서 감지된 외부 서비스들을 자산 목록으로 관리한다.
    대시보드의 'AI·IT 거버넌스' 화면이 이 클래스의 데이터를 보여준다.
    """

    def __init__(self):
        # 도메인별 추적 레코드: domain -> ShadowAIAsset
        self.assets: Dict[str, ShadowAIAsset] = {}

        # 도메인별 고유 IP 및 사용자 집합 추적
        # set(집합)을 쓰는 이유: 같은 사람이 100번 접속해도 사용자 1명으로 세기 위해서다.
        # 중복이 자동으로 제거되므로 len()을 하면 실제 사용자 수가 나온다.
        self._domain_users: Dict[str, set] = {}
        self._domain_counts: Dict[str, int] = {}   # 도메인별 총 접속 횟수

        # sync_railway_events() 가 계산한 도메인별 집계 결과를 그대로 보관한다.
        # 화면에서 "이 도메인에 누가 몇 번 접속했나"를 보여줄 때 쓴다.
        self._railway_domain_stats: Dict[str, Dict[str, Any]] = {}

        self._init_defaults()

    def _init_defaults(self):
        """
        기본 시연용 데이터 초기화

        대시보드를 처음 켰을 때 거버넌스 화면이 비어 있지 않도록
        자주 쓰이는 서비스 6개를 미리 채워 넣는다. 인원수와 접속 건수는 가짜 값이다.
        실제 로그가 들어오면 sync_railway_events() 가 이 값들을 덮어쓴다.
        """
        defaults = [
            ("chatgpt.com", 3, 14, 52, "매일 (실시간 감지 집중)", Severity.HIGH, "사용자 입력 데이터가 AI 모델 재학습에 활용될 수 있어 사내 기밀 유출 고위험", SanctionStatus.UNAPPROVED),
            ("wetransfer.com", 1, 2, 8, "비정기 (간헐 접속)", Severity.HIGH, "익명 파일 전송 서비스로 사내 감사 로그 추적 불가 및 데이터 유출 취약", SanctionStatus.BLOCKED),
            ("claude.ai", 2, 5, 21, "주 4회 (정기 사용)", Severity.HIGH, "긴 문서 분석 기능으로 인해 대량 사내 보고서 업로드 위험 존재", SanctionStatus.UNAPPROVED),
            ("dropbox.com", 2, 4, 18, "주 3회", Severity.MEDIUM, "개인 계정 사용 추정. 외부 협업 시 링크 유출에 따른 무단 다운로드 위험", SanctionStatus.UNAPPROVED),
            ("notion.so", 1, 1, 4, "1회 관찰", Severity.LOW, "단순 문서 작성 용도 관찰 중. 현재까지 대용량 파일 전송 미탐지", SanctionStatus.UNAPPROVED),
            ("slack.com", 8, 42, 126, "매일 (전사 기본)", Severity.LOW, "사내 정식 계약 체결 도구 (SSO 연동 및 데이터 보존 정책 적용됨)", SanctionStatus.APPROVED),
        ]
        for domain, depts, users, count, freq, risk, diag, status in defaults:
            self.assets[domain] = ShadowAIAsset(
                domain=domain,
                service_name=KNOWN_SAAS_DATABASE.get(domain, {}).get("service_name", domain.capitalize()),
                category=KNOWN_SAAS_DATABASE.get(domain, {}).get("category", "외부 SaaS"),
                department_count=depts,
                user_count=users,
                usage_frequency=freq,
                risk_level=risk,
                ai_diagnosis=diag,
                sanction_status=status,
                recommended_alternative=None,
                detected_at=datetime.now(),
                access_count=count,
                active_users=[f"임직원 {users}명"]
            )

    def sync_railway_events(self, railway_events: List[Dict[str, Any]]):
        """
        Railway 중앙 서버에서 수집된 실제 이벤트 로그를 분석하여
        각 도메인의 접속 건수, 임직원 수, 사용 빈도를 실시간 카운트 형식으로 갱신하고,
        신규 외부 AI/SaaS 도메인을 거버넌스 자산 목록에 동적으로 추가.

        [흐름]
          1) 로그를 도메인별로 묶어 집계한다 (접속 횟수 / 사용자 / IP / 파일업로드 시도)
          2) 이미 알고 있는 자산은 그 집계로 숫자를 갱신한다
          3) 처음 보는 도메인 중 AI·클라우드로 보이거나 2회 이상 접속된 것은 자산으로 새로 등록한다

        [주의] 이 함수는 화면 쪽에서 주기적으로 불러줘야 한다.
          엔진이 스스로 서버를 조회하지 않는다. 로그를 받아서 처리만 한다.
        """
        if not railway_events:
            return

        # 도메인 → {count, users, ips, last_time, file_uploads}
        domain_stats: Dict[str, Dict[str, Any]] = {}

        for ev in railway_events:
            # --- 도메인 정리 ---
            # 로그에 "https://chatgpt.com/chat?a=1" 처럼 들어올 수 있으므로
            # 프로토콜·경로·포트를 차례로 떼어내 순수 도메인만 남긴다.
            raw_target = ev.get("target") or ""
            target = raw_target.strip().lower()
            if not target or target in ("unknown", "none", "null", "-"):
                continue
            if "://" in target:
                target = target.split("://")[1]
            if "/" in target:
                target = target.split("/")[0]
            if ":" in target:
                target = target.split(":")[0]

            if "." not in target:
                continue   # 도메인 형태가 아니면 버린다

            # 우리 서버 자신과 로컬 주소는 거버넌스 대상이 아니다.
            # (Agent가 서버로 로그를 보내는 것까지 '섀도우 IT 접속'으로 세면 안 된다)
            if any(ign in target for ign in ["railway.app", "localhost", "127.0.0.1", "0.0.0.0"]):
                continue

            user = ev.get("user_name") or ev.get("user") or "User"
            ip = ev.get("local_ip") or "unknown"
            ev_time = ev.get("event_time")
            ev_type = ev.get("event_type") or "WEB_ACCESS"

            if target not in domain_stats:
                domain_stats[target] = {
                    "count": 0,
                    "users": set(),
                    "ips": set(),
                    "last_time": ev_time,
                    "file_uploads": 0
                }
            
            domain_stats[target]["count"] += 1
            if user and user != "unknown":
                domain_stats[target]["users"].add(user)
            if ip and ip != "unknown":
                domain_stats[target]["ips"].add(ip)
            if ev_type == "FILE_UPLOAD_ATTEMPT":
                domain_stats[target]["file_uploads"] += 1

        self._railway_domain_stats = domain_stats   # 화면에서 꺼내 쓸 수 있게 보관

        # 1. 기존 자산 통계 실시간 업데이트
        for domain, asset in self.assets.items():
            if domain in domain_stats:
                st = domain_stats[domain]
                rly_count = st["count"]
                rly_users = st["users"]
                
                # 실시간 카운트 반영
                base_count = getattr(asset, "access_count", 0) or 10
                asset.access_count = base_count + rly_count
                
                # 시연용으로 넣어둔 "임직원 14명" 같은 가짜 항목은 걷어내고
                # 실제 수집된 사용자 이름으로 대체한다.
                cur_users = set(asset.active_users or [])
                cur_users = {u for u in cur_users if not u.startswith("임직원 ")}
                cur_users |= rly_users
                asset.active_users = sorted(list(cur_users))
                asset.user_count = max(len(cur_users), asset.user_count)
                asset.department_count = max(len(st["ips"]), asset.department_count)
                
                # 사용 빈도 실시간 계산
                if rly_count >= 10 or st["file_uploads"] > 0:
                    asset.usage_frequency = f"실시간 급증 (누적 {asset.access_count}건 / 전송시도 {st['file_uploads']}건)"
                elif rly_count >= 3:
                    asset.usage_frequency = f"실시간 빈번 (누적 {asset.access_count}건)"
                elif rly_count >= 1:
                    asset.usage_frequency = f"실시간 감지 (누적 {asset.access_count}건)"
            else:
                if not getattr(asset, "access_count", 0):
                    asset.access_count = asset.user_count * 3

        # 2. Railway에서 새롭게 발견된 외부 AI / SaaS 도메인 등록
        #    모든 도메인을 다 등록하면 목록이 광고·CDN 주소로 가득 찬다.
        #    그래서 AI·클라우드로 보이거나(이름 기준) 2회 이상 접속된 것만 올린다.
        for domain, st in domain_stats.items():
            if domain not in self.assets:
                is_ai_or_cloud = any(k in domain for k in ["ai", "gpt", "gemini", "claude", "bot", "cloud", "kakao", "datadog", "google", "drive", "share", "github", "notion", "poma"])
                if is_ai_or_cloud or st["count"] >= 2:
                    heuristic = _fallback_heuristic_analysis(domain)
                    user_list = sorted(list(st["users"])) if st["users"] else ["User"]
                    self.assets[domain] = ShadowAIAsset(
                        domain=domain,
                        service_name=heuristic["service_name"],
                        category=heuristic["category"],
                        department_count=max(1, len(st["ips"])),
                        user_count=max(1, len(user_list)),
                        usage_frequency=f"실시간 감지 ({st['count']}건 접속)",
                        risk_level=heuristic["risk_level"],
                        ai_diagnosis=heuristic["ai_diagnosis"],
                        sanction_status=SanctionStatus.UNAPPROVED,
                        recommended_alternative=None,
                        detected_at=datetime.now(),
                        access_count=st["count"],
                        active_users=user_list
                    )

    def get_railway_domain_stats(self) -> Dict[str, Dict[str, Any]]:
        """
        Railway에서 수집된 도메인별 집계 통계 반환

        dict()로 복사해서 돌려주는 이유: 화면 쪽에서 실수로 값을 바꿔도
        엔진 내부 데이터가 망가지지 않게 하기 위함이다.
        """
        return dict(self._railway_domain_stats)

    def get_connection_count(self, domain: str) -> int:
        """
        도메인별 실시간 접속/질의 누적 건수 반환

        자산에 기록된 access_count 를 우선 쓰고, 없으면 내부 카운터를 쓴다.
        둘 다 없으면 1을 돌려준다 (0으로 나누는 계산을 막기 위한 기본값).
        """
        if domain in self.assets and getattr(self.assets[domain], "access_count", 0):
            return self.assets[domain].access_count
        return self._domain_counts.get(domain, 1)

    def process_dns_event(self, event: SecurityEvent):
        """
        새로운 DNS/웹/에이전트/확장프로그램 이벤트 수신 시 통계 누적 및 판별

        접속 이벤트가 들어올 때마다 호출된다.
          · 처음 보는 도메인이면 → 자산으로 새로 등록
          · 이미 아는 도메인이면 → 사용자 수와 접속 건수만 갱신

        [수정됨] 예전에는 storage/memory_store.py 가 DNS 소스만 걸러서 넘기는 바람에
          실제 수집 로그(WINDOWS_AGENT / CHROME_EXTENSION)가 여기까지 오지 못했다.
          지금은 team_events 를 전부 넘기고, 소스 판별은 아래 첫 줄에서 한다.
        """
        # 도메인 정보가 없는 이벤트(DB 조회 등)는 거버넌스 대상이 아니므로 건너뛴다
        if event.log_source not in [LogSource.DNS, LogSource.WEB, LogSource.WINDOWS_AGENT, LogSource.CHROME_EXTENSION] or not event.target.domain:
            return

        domain = event.target.domain.lower()
        src_ip = event.actor.src_ip
        user = event.actor.user_id

        if domain not in self._domain_users:
            self._domain_users[domain] = set()
            if domain not in self._domain_counts:
                self._domain_counts[domain] = 0

        # 사용자 이름이 있으면 이름으로, 없으면 IP로 센다.
        # 집합이므로 같은 사람이 여러 번 와도 1명으로 계산된다.
        self._domain_users[domain].add(user or src_ip)
        self._domain_counts[domain] += 1         # 접속 횟수는 매번 증가

        # 도메인이 자산 목록에 없으면 신규 생성
        # KNOWN_SAAS_DATABASE에 있으면 그 정보를, 없으면 'LLM 분석 대기' 상태로 등록한다.
        if domain not in self.assets:
            info = KNOWN_SAAS_DATABASE.get(domain, {
                "service_name": domain.capitalize(),
                "category": "미확인 외부 서비스 (LLM 분석 대기)",
                "default_status": SanctionStatus.UNAPPROVED,
                "default_risk": Severity.MEDIUM,
                "ai_diagnosis": "미등록 도메인 - LLM이 서비스 성격과 데이터 보안 위험을 분석 중입니다."
            })
            self.assets[domain] = ShadowAIAsset(
                domain=domain,
                service_name=info["service_name"],
                category=info["category"],
                department_count=1,
                user_count=len(self._domain_users[domain]),
                usage_frequency="실시간 감지",
                risk_level=info["default_risk"],
                ai_diagnosis=info["ai_diagnosis"],
                sanction_status=info["default_status"],
                recommended_alternative=None,
                detected_at=event.timestamp,
                access_count=self._domain_counts[domain],
                active_users=sorted(list(self._domain_users[domain]))
            )
        else:
            # 기존 자산 사용 카운트 갱신
            # max()를 쓰는 이유: 미리 넣어둔 시연용 인원수(예: 14명)가
            # 실제 감지 인원수(1명)보다 클 수 있는데, 그때 숫자가 줄어들면 어색하기 때문.
            self.assets[domain].user_count = max(self.assets[domain].user_count, len(self._domain_users[domain]))
            self.assets[domain].access_count += 1

    def update_sanction_status(self, domain: str, new_status: SanctionStatus) -> Optional[ShadowAIAsset]:
        """
        양성화/차단 등 승인 상태 변경

        관리자가 거버넌스 화면에서 '승인' 또는 '차단' 버튼을 누르면 호출된다.
        승인하면 위험도를 LOW로, 차단하면 CRITICAL로 함께 바꾼다.
        (차단된 도메인을 목록 맨 위에 띄워서 관리자가 바로 알아보게 하려는 것)

        ※ 상태 변경 이력은 남기지 않는다. 누가 언제 승인했는지 추적하려면 별도 기록이 필요하다.
        """
        if domain in self.assets:
            self.assets[domain].sanction_status = new_status
            if new_status == SanctionStatus.APPROVED:
                self.assets[domain].risk_level = Severity.LOW
            elif new_status == SanctionStatus.BLOCKED:
                self.assets[domain].risk_level = Severity.CRITICAL
            return self.assets[domain]
        return None

    def get_all_assets(self) -> List[ShadowAIAsset]:
        """
        위험도 높은 순서로 정렬하여 반환

        Severity는 문자열이라 그냥 정렬하면 알파벳 순(CRITICAL, HIGH, LOW, MEDIUM)이 되어버린다.
        그래서 각 등급에 번호를 매긴 표(severity_order)를 만들어 그 번호로 정렬한다.
        """
        severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
        return sorted(list(self.assets.values()), key=lambda x: severity_order.get(x.risk_level, 4))

    def analyze_and_register_domain(self, domain: str, api_key: Optional[str] = None, live_context: Optional[Dict[str, Any]] = None) -> ShadowAIAsset:
        """
        Gemini AI 또는 지능형 휴리스틱 분석을 실행하여 도메인 정보를 등록하거나 업데이트

        관리자가 거버넌스 화면에서 도메인을 직접 입력하고 '진단' 버튼을 눌렀을 때 호출된다.
        이미 등록된 도메인이면 분석 결과로 내용을 갱신하고, 없으면 새 자산으로 추가한다.
        live_context 를 함께 넘기면 실제 수집 통계까지 반영된 진단을 받는다.
        """
        d = domain.strip().lower()

        # http://, https:// 및 경로 제거
        # 사용자가 "https://chatgpt.com/chat" 처럼 입력해도 "chatgpt.com"만 남기기 위한 정리 작업
        if "://" in d:
            d = d.split("://")[1]
        if "/" in d:
            d = d.split("/")[0]

        analysis = analyze_domain_with_gemini(d, api_key=api_key, live_context=live_context)

        access_cnt = live_context.get("count", 1) if live_context else 1
        user_list = sorted(list(live_context.get("users", ["User"]))) if live_context else ["User"]

        if d in self.assets:
            asset = self.assets[d]
            asset.service_name = analysis.get("service_name", asset.service_name)
            asset.category = analysis.get("category", asset.category)
            asset.risk_level = analysis.get("risk_level", asset.risk_level)
            asset.ai_diagnosis = analysis.get("ai_diagnosis", asset.ai_diagnosis)
            asset.recommended_alternative = None
            if live_context:
                asset.access_count = max(asset.access_count, access_cnt)
                asset.user_count = max(asset.user_count, len(user_list))
                asset.active_users = sorted(list(set(asset.active_users) | set(user_list)))
                asset.usage_frequency = f"실시간 감지 (누적 {asset.access_count}건)"
        else:
            asset = ShadowAIAsset(
                domain=d,
                service_name=analysis.get("service_name", d.capitalize()),
                category=analysis.get("category", "외부 AI/SaaS"),
                department_count=1,
                user_count=len(user_list),
                usage_frequency=f"신규 실시간 분석 ({access_cnt}건 감지)",
                risk_level=analysis.get("risk_level", Severity.HIGH),
                ai_diagnosis=analysis.get("ai_diagnosis", "Gemini AI 실시간 분석 완료"),
                sanction_status=SanctionStatus.UNAPPROVED,
                recommended_alternative=None,
                detected_at=datetime.now(),
                access_count=access_cnt,
                active_users=user_list
            )
            self.assets[d] = asset
        return asset

