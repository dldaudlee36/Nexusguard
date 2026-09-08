"""
NexusGuard - Shadow IT & AI Governance Engine
DNS 질의 기반 섀도우 IT/AI 식별, 위험도 산출 및 양성화 워크플로 관리 모듈
"""

from typing import Dict, List, Optional
from datetime import datetime
from nexusguard.schemas.event import SecurityEvent, LogSource
from nexusguard.schemas.incident import ShadowAIAsset, Severity, SanctionStatus


# 사내 정적 SaaS & AI 지식 베이스
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
    """
    import os
    import json

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
                    break
            except Exception:
                continue

        if not response or not response.text:
            return _fallback_heuristic_analysis(domain)

        text = response.text.strip()
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0].strip()
        elif "```" in text:
            text = text.split("```")[1].split("```")[0].strip()
        data = json.loads(text)
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
        return _fallback_heuristic_analysis(domain)


def _fallback_heuristic_analysis(domain: str) -> Dict[str, Any]:
    d = domain.lower()
    if any(k in d for k in ["ai", "gpt", "bot", "deep", "claude", "gemini", "copilot", "llm", "perplexity", "sora", "midjourney", "hugging"]):
        return {
            "service_name": domain.capitalize(),
            "category": "생성형 AI 및 LLM 서비스",
            "risk_level": Severity.HIGH,
            "ai_diagnosis": "미등록 생성형 AI 서비스: 프롬프트 입력 데이터의 외부 모델 재학습 및 기밀 유출 고위험",
            "alternative": None
        }
    elif any(k in d for k in ["drive", "box", "cloud", "share", "transfer", "sync", "mega", "storage", "datadog", "kakao"]):
        return {
            "service_name": domain.capitalize(),
            "category": "클라우드 서비스 및 데이터 전송",
            "risk_level": Severity.MEDIUM,
            "ai_diagnosis": "외부 클라우드 서비스 연동 확인. 대용량 데이터 반출 및 비인가 접근 여부 모니터링 필요",
            "alternative": None
        }
    else:
        return {
            "service_name": domain.capitalize(),
            "category": "일반 외부 웹/SaaS 서비스",
            "risk_level": Severity.LOW,
            "ai_diagnosis": "정상 웹 트래픽 관찰 중. 현재까지 민감 데이터 대량 전송 징후 없음",
            "alternative": None
        }


class ShadowAIGovernanceEngine:
    """섀도우 IT 및 생성형 AI 거버넌스 분석기"""

    def __init__(self):
        # 도메인별 추적 레코드: domain -> ShadowAIAsset
        self.assets: Dict[str, ShadowAIAsset] = {}
        # 도메인별 고유 IP 및 사용자 집합 추적
        self._domain_users: Dict[str, set] = {}
        self._domain_counts: Dict[str, int] = {}
        self._railway_domain_stats: Dict[str, Dict[str, Any]] = {}
        self._init_defaults()

    def _init_defaults(self):
        """기본 시연용 데이터 초기화"""
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
        """
        if not railway_events:
            return

        domain_stats: Dict[str, Dict[str, Any]] = {}

        for ev in railway_events:
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
                continue
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

        self._railway_domain_stats = domain_stats

        # 1. 기존 자산 통계 실시간 업데이트
        for domain, asset in self.assets.items():
            if domain in domain_stats:
                st = domain_stats[domain]
                rly_count = st["count"]
                rly_users = st["users"]
                
                # 실시간 카운트 반영
                base_count = getattr(asset, "access_count", 0) or 10
                asset.access_count = base_count + rly_count
                
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
        """Railway에서 수집된 도메인별 집계 통계 반환"""
        return dict(self._railway_domain_stats)

    def process_dns_event(self, event: SecurityEvent):
        """새로운 DNS/웹/에이전트/확장프로그램 이벤트 수신 시 통계 누적 및 판별"""
        if event.log_source not in [LogSource.DNS, LogSource.WEB, LogSource.WINDOWS_AGENT, LogSource.CHROME_EXTENSION] or not event.target.domain:
            return

        domain = event.target.domain.lower()
        src_ip = event.actor.src_ip
        user = event.actor.user_id

        if domain not in self._domain_users:
            self._domain_users[domain] = set()
            self._domain_counts[domain] = 0

        self._domain_users[domain].add(user or src_ip)
        self._domain_counts[domain] += 1

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
            self.assets[domain].user_count = max(self.assets[domain].user_count, len(self._domain_users[domain]))
            self.assets[domain].access_count += 1

    def update_sanction_status(self, domain: str, new_status: SanctionStatus) -> Optional[ShadowAIAsset]:
        """양성화/차단 등 승인 상태 변경"""
        if domain in self.assets:
            self.assets[domain].sanction_status = new_status
            if new_status == SanctionStatus.APPROVED:
                self.assets[domain].risk_level = Severity.LOW
            elif new_status == SanctionStatus.BLOCKED:
                self.assets[domain].risk_level = Severity.CRITICAL
            return self.assets[domain]
        return None

    def get_all_assets(self) -> List[ShadowAIAsset]:
        """위험도 높은 순서로 정렬하여 반환"""
        severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
        return sorted(list(self.assets.values()), key=lambda x: severity_order.get(x.risk_level, 4))

    def analyze_and_register_domain(self, domain: str, api_key: Optional[str] = None, live_context: Optional[Dict[str, Any]] = None) -> ShadowAIAsset:
        """Gemini AI 또는 지능형 휴리스틱 분석을 실행하여 도메인 정보를 등록하거나 업데이트"""
        d = domain.strip().lower()
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

