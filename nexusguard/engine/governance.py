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


def analyze_domain_with_gemini(domain: str, api_key: Optional[str] = None) -> Dict[str, Any]:
    """
    Google Gemini API(google-genai)를 활용하여 미등록 도메인의 용도, 재학습 위험도, 사내 대체 도구를 분석.
    API 키가 없거나 실패 시 지능형 휴리스틱 룰베이스로 안전하게 폴백.
    """
    import os
    import json
    import logging

    key = api_key or os.environ.get("GEMINI_API_KEY")
    if not key:
        return _fallback_heuristic_analysis(domain)

    try:
        from google import genai
        client = genai.Client(api_key=key)
        prompt = f"""
당신은 엔터프라이즈 보안관제 및 Shadow AI 거버넌스 전문가입니다.
사내 직원이 접속한 아래 외부 도메인을 분석하여 보안 평가 결과를 JSON으로 응답하세요.

대상 도메인: {domain}

반드시 아래 JSON 형식만 반환하세요:
{{
    "service_name": "서비스명 (예: Perplexity AI)",
    "category": "서비스 카테고리 (예: 검색형 생성형 AI / 클라우드 파일 공유 / 디자인 AI 등)",
    "risk_level": "HIGH / MEDIUM / LOW 중 하나",
    "ai_diagnosis": "보안 진단 소견 (1~2문장, 사용자 프롬프트 데이터의 AI 모델 재학습 여부 및 기밀 유출 위험성 평가)",
    "alternative": "권고 사내 대체 도구 (예: 사내 프라이빗 AI 포털 (Aegis-GenAI) 등)"
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
            "alternative": data.get("alternative", "사내 보안 승인 서비스")
        }
    except Exception as e:
        return _fallback_heuristic_analysis(domain)


def _fallback_heuristic_analysis(domain: str) -> Dict[str, Any]:
    d = domain.lower()
    if any(k in d for k in ["ai", "gpt", "bot", "deep", "claude", "gemini", "copilot", "llm", "perplexity", "sora", "midjourney", "hugging"]):
        return {
            "service_name": domain.capitalize(),
            "category": "생성형 AI 및 LLM 서비스",
            "risk_level": Severity.HIGH,
            "ai_diagnosis": "미등록 생성형 AI 서비스: 프롬프트 입력 데이터의 외부 모델 재학습 및 기밀 유출 고위험",
            "alternative": "사내 프라이빗 AI 포털 (Aegis-GenAI)"
        }
    elif any(k in d for k in ["drive", "box", "cloud", "share", "transfer", "sync", "mega", "storage"]):
        return {
            "service_name": domain.capitalize(),
            "category": "클라우드 스토리지 및 파일 전송",
            "risk_level": Severity.MEDIUM,
            "ai_diagnosis": "개인 클라우드 저장소 연동 가능성. 링크 공유 및 대용량 파일 반출 모니터링 필요",
            "alternative": "사내 보안 파일 저장소 (SecureDrive)"
        }
    else:
        return {
            "service_name": domain.capitalize(),
            "category": "일반 외부 웹/SaaS 서비스",
            "risk_level": Severity.LOW,
            "ai_diagnosis": "정상 웹 트래픽 관찰 중. 현재까지 민감 데이터 대량 전송 징후 없음",
            "alternative": "사내 표준 업무망"
        }


class ShadowAIGovernanceEngine:
    """섀도우 IT 및 생성형 AI 거버넌스 분석기"""

    def __init__(self):
        # 도메인별 추적 레코드: domain -> ShadowAIAsset
        self.assets: Dict[str, ShadowAIAsset] = {}
        # 도메인별 고유 IP 집합 추적
        self._domain_users: Dict[str, set] = {}
        self._domain_counts: Dict[str, int] = {}
        self._init_defaults()

    def _init_defaults(self):
        """기본 시연용 데이터 초기화"""
        defaults = [
            ("slack.com", 8, 42, "매일"),
            ("chatgpt.com", 3, 14, "매일"),
            ("dropbox.com", 2, 4, "주 3회"),
            ("notion.so", 1, 1, "1회 관찰"),
            ("wetransfer.com", 1, 2, "비정기"),
            ("claude.ai", 2, 5, "주 4회"),
        ]
        for domain, depts, users, freq in defaults:
            info = KNOWN_SAAS_DATABASE.get(domain, {
                "service_name": domain,
                "category": "기타 웹 서비스",
                "default_status": SanctionStatus.UNAPPROVED,
                "default_risk": Severity.MEDIUM,
                "ai_diagnosis": "미등록 외부 도메인. 사용 현황 모니터링 필요",
                "alternative": "사내 승인 서비스"
            })
            self.assets[domain] = ShadowAIAsset(
                domain=domain,
                service_name=info["service_name"],
                category=info["category"],
                department_count=depts,
                user_count=users,
                usage_frequency=freq,
                risk_level=info["default_risk"],
                ai_diagnosis=info["ai_diagnosis"],
                sanction_status=info["default_status"],
                recommended_alternative=info["alternative"],
                detected_at=datetime.now()
            )

    def process_dns_event(self, event: SecurityEvent):
        """새로운 DNS 이벤트 수신 시 통계 누적 및 판별"""
        if event.log_source != LogSource.DNS or not event.target.domain:
            return

        domain = event.target.domain.lower()
        src_ip = event.actor.src_ip

        if domain not in self._domain_users:
            self._domain_users[domain] = set()
            self._domain_counts[domain] = 0

        self._domain_users[domain].add(src_ip)
        self._domain_counts[domain] += 1

        # 도메인이 자산 목록에 없으면 신규 생성
        if domain not in self.assets:
            info = KNOWN_SAAS_DATABASE.get(domain, {
                "service_name": domain.capitalize(),
                "category": "미확인 외부 서비스 (LLM 분석 대기)",
                "default_status": SanctionStatus.UNAPPROVED,
                "default_risk": Severity.MEDIUM,
                "ai_diagnosis": "미등록 도메인 - LLM이 서비스 성격과 데이터 보안 위험을 분석 중입니다.",
                "alternative": "사내 보안팀 문의"
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
                recommended_alternative=info["alternative"],
                detected_at=event.timestamp
            )
        else:
            # 기존 자산 사용 카운트 갱신
            self.assets[domain].user_count = max(self.assets[domain].user_count, len(self._domain_users[domain]))

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

    def analyze_and_register_domain(self, domain: str, api_key: Optional[str] = None) -> ShadowAIAsset:
        """Gemini AI 또는 지능형 휴리스틱 분석을 실행하여 도메인 정보를 등록하거나 업데이트"""
        d = domain.strip().lower()
        # http://, https:// 및 경로 제거
        if "://" in d:
            d = d.split("://")[1]
        if "/" in d:
            d = d.split("/")[0]

        analysis = analyze_domain_with_gemini(d, api_key=api_key)

        if d in self.assets:
            asset = self.assets[d]
            asset.service_name = analysis.get("service_name", asset.service_name)
            asset.category = analysis.get("category", asset.category)
            asset.risk_level = analysis.get("risk_level", asset.risk_level)
            asset.ai_diagnosis = analysis.get("ai_diagnosis", asset.ai_diagnosis)
            asset.recommended_alternative = analysis.get("alternative", asset.recommended_alternative)
        else:
            asset = ShadowAIAsset(
                domain=d,
                service_name=analysis.get("service_name", d.capitalize()),
                category=analysis.get("category", "외부 AI/SaaS"),
                department_count=1,
                user_count=1,
                usage_frequency="신규 AI 분석 감지",
                risk_level=analysis.get("risk_level", Severity.HIGH),
                ai_diagnosis=analysis.get("ai_diagnosis", "Gemini AI 실시간 분석 완료"),
                sanction_status=SanctionStatus.UNAPPROVED,
                recommended_alternative=analysis.get("alternative", "사내 보안 승인 서비스"),
                detected_at=datetime.now()
            )
            self.assets[d] = asset
        return asset

