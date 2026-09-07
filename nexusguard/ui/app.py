"""
NexusGuard - Unified Security Operations & Governance Dashboard
Zero Trust 기반 다기종 로그 상관분석 & 섀도우 AI 거버넌스 통합 웹 대시보드
"""

import sys
from pathlib import Path

# 프로젝트 루트 디렉토리를 sys.path 최우선에 등록하여 로컬 및 클라우드 실행 보장
_root_dir = Path(__file__).resolve().parent.parent.parent
if str(_root_dir) not in sys.path:
    sys.path.insert(0, str(_root_dir))

import streamlit as st
import pandas as pd
import base64
import streamlit.components.v1 as components
from datetime import datetime, timedelta
from nexusguard.storage import get_context
from nexusguard.schemas import Severity, SanctionStatus, IncidentStatus, Incident
from nexusguard.schemas.event import SecurityEvent, LogSource, EventAction, Actor, Target, PayloadMetadata

# 1. 페이지 기본 설정
st.set_page_config(
    page_title="Shadow AI Dashboard | NexusGuard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# 2. 다크 테마 및 인터랙티브 툴팁 CSS
st.markdown("""
<style>
    /* 메인 배경 및 폰트 */
    .stApp {
        background-color: #07111f;
        color: #f5f7fb;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }
    
    /* 사이드바 */
    section[data-testid="stSidebar"] {
        background-color: #0c1727 !important;
        border-right: 1px solid #1c2b42;
        min-width: 290px !important;
    }

    /* 🌟 사이드바 라디오 네비게이션 헤더 라벨 */
    section[data-testid="stSidebar"] div[data-testid="stRadio"] > label {
        background: transparent !important;
        border: none !important;
        box-shadow: none !important;
        padding: 0 0 6px 4px !important;
        font-size: 13px !important;
        font-weight: 700 !important;
        color: #94a3b8 !important;
        letter-spacing: 0.5px !important;
        cursor: default !important;
    }
    section[data-testid="stSidebar"] div[data-testid="stRadio"] div[role="radiogroup"] {
        gap: 8px !important;
        display: flex !important;
        flex-direction: column !important;
        width: 100% !important;
    }
    /* 각 옵션 항목 박스 카드 */
    section[data-testid="stSidebar"] div[data-testid="stRadio"] div[role="radiogroup"] label {
        background-color: #111e33 !important;
        border: 1px solid #1c2e47 !important;
        border-radius: 10px !important;
        padding: 11px 14px !important;
        margin: 0 !important;
        transition: all 0.2s ease-in-out !important;
        cursor: pointer !important;
        box-shadow: 0 2px 6px rgba(0, 0, 0, 0.25) !important;
        display: flex !important;
        align-items: center !important;
        width: 100% !important;
        box-sizing: border-box !important;
    }
    section[data-testid="stSidebar"] div[data-testid="stRadio"] div[role="radiogroup"] label:hover {
        background-color: #172a48 !important;
        border-color: #3b82f6 !important;
        transform: translateX(4px) !important;
        box-shadow: 0 4px 14px rgba(59, 130, 246, 0.25) !important;
    }
    /* 선택된 활성 항목 강조 박스 */
    section[data-testid="stSidebar"] div[data-testid="stRadio"] div[role="radiogroup"] label:has(input:checked) {
        background: linear-gradient(135deg, #132746 0%, #1c3d6e 100%) !important;
        border: 1.5px solid #38bdf8 !important;
        box-shadow: 0 4px 16px rgba(56, 189, 248, 0.3) !important;
    }
    section[data-testid="stSidebar"] div[data-testid="stRadio"] div[role="radiogroup"] label p,
    section[data-testid="stSidebar"] div[data-testid="stRadio"] div[role="radiogroup"] label span,
    section[data-testid="stSidebar"] div[data-testid="stRadio"] div[role="radiogroup"] label div {
        font-size: 14px !important;
        font-weight: 600 !important;
        color: #f1f5f9 !important;
    }

    /* KPI 카드 스타일 */
    .kpi-card {
        background: #0d1a2b;
        border: 1px solid #1c2e47;
        border-radius: 14px;
        padding: 20px 24px;
        margin-bottom: 15px;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
    }
    .kpi-title {
        font-size: 14px;
        font-weight: 600;
        color: #9fb0c8;
        margin-bottom: 8px;
    }
    .kpi-value {
        font-size: 38px;
        font-weight: 700;
        color: #ffffff;
        letter-spacing: -1px;
    }
    .kpi-sub {
        font-size: 12px;
        color: #6c7f99;
        margin-top: 4px;
    }
    
    /* 위험도 텍스트 컬러 */
    .critical-text { color: #ff5b6b !important; }
    .high-text { color: #ff7b88 !important; }
    .medium-text { color: #ffbf4b !important; }
    .low-text { color: #62d487 !important; }
    
    /* 박스 타이틀 */
    .box-title {
        font-size: 18px;
        font-weight: 700;
        color: #f5f7fb;
        margin-bottom: 16px;
        display: flex;
        align-items: center;
        gap: 8px;
    }

    /* 뱃지 */
    .badge {
        padding: 4px 10px;
        border-radius: 6px;
        font-size: 12px;
        font-weight: 700;
        display: inline-block;
    }
    .badge-critical { background: #5b2028; color: #ff9aa4; border: 1px solid #ff5b6b; }
    .badge-high { background: #4d232a; color: #ff8591; border: 1px solid #ff7b88; }
    .badge-medium { background: #4d3a19; color: #ffd169; border: 1px solid #ffbf4b; }
    .badge-low { background: #163824; color: #86efac; border: 1px solid #62d487; }
    
    /* 공격 타임라인 체인 */
    .timeline-step {
        display: inline-flex;
        align-items: center;
        padding: 10px 16px;
        background: #132238;
        border-radius: 8px;
        font-size: 13px;
        font-weight: 600;
        margin-right: 8px;
        margin-bottom: 8px;
        border: 1px solid #233754;
    }
    .timeline-arrow {
        color: #4c8cff;
        font-weight: bold;
        margin: 0 4px;
    }
    
    /* 근거 박스 */
    .evidence-item {
        color: #9ee0b2;
        font-size: 13px;
        margin-bottom: 6px;
        display: flex;
        align-items: center;
        gap: 6px;
    }

    /* =================================================== */
    /* 🌟 드롭다운 메뉴 시인성 극대화 커스텀 스타일 */
    /* =================================================== */
    div[data-testid="stSelectbox"] label {
        font-size: 16px !important;
        font-weight: 700 !important;
        color: #60a5fa !important;
        margin-bottom: 8px !important;
        display: flex !important;
        align-items: center !important;
        gap: 6px !important;
    }
    div[data-testid="stSelectbox"] div[data-baseweb="select"] {
        background-color: transparent !important;
        border: none !important;
    }
    div[data-testid="stSelectbox"] div[data-baseweb="select"] > div {
        min-height: 54px !important;
        background-color: #0b1a2e !important;
        border: 2px solid #3b82f6 !important;
        border-radius: 12px !important;
        box-shadow: 0 4px 16px rgba(37, 99, 235, 0.25) !important;
        padding: 4px 14px !important;
        display: flex !important;
        align-items: center !important;
        box-sizing: border-box !important;
        transition: all 0.2s ease-in-out !important;
    }
    div[data-testid="stSelectbox"] div[data-baseweb="select"] > div:hover {
        border-color: #60a5fa !important;
        box-shadow: 0 6px 22px rgba(59, 130, 246, 0.45) !important;
        background-color: #0e223d !important;
    }
    /* 선택 상자 내부 텍스트 폰트 및 스타일 */
    div[data-testid="stSelectbox"] div[data-baseweb="select"] [data-testid="stMarkdownContainer"] p,
    div[data-testid="stSelectbox"] div[data-baseweb="select"] span {
        color: #ffffff !important;
        font-size: 15px !important;
        font-weight: 600 !important;
        line-height: 1.5 !important;
    }
    /* 우측 토글 화살표(Chevron): 박스 우측 내부에 완벽 고정 */
    div[data-testid="stSelectbox"] div[data-baseweb="select"] svg {
        fill: #60a5fa !important;
        width: 20px !important;
        height: 20px !important;
        flex-shrink: 0 !important;
    }
    /* 드롭다운 가상 목록 스타일 (클릭 시 펼쳐지는 목록) */
    ul[data-testid="stSelectboxVirtualDropdown"] {
        background-color: #0b1a2e !important;
        border: 2px solid #3b82f6 !important;
        border-radius: 12px !important;
        box-shadow: 0 12px 36px rgba(0, 0, 0, 0.85) !important;
        padding: 6px 0 !important;
    }
    ul[data-testid="stSelectboxVirtualDropdown"] li {
        font-size: 14px !important;
        line-height: 1.5 !important;
        padding: 12px 16px !important;
        min-height: 50px !important;
        color: #e2e8f0 !important;
        border-bottom: 1px solid #172a45 !important;
        display: flex !important;
        align-items: center !important;
    }
    ul[data-testid="stSelectboxVirtualDropdown"] li:hover,
    ul[data-testid="stSelectboxVirtualDropdown"] li[aria-selected="true"] {
        background-color: #1e3a8a !important;
        color: #ffffff !important;
    }

    /* =================================================== */
    /* 💬 마우스 커서 호버 시 팝업(Tooltip) 스타일 */
    /* =================================================== */
    .tooltip-container {
        position: relative;
        display: inline-flex;
        align-items: center;
        cursor: pointer;
    }
    .tooltip-icon {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        transition: transform 0.2s ease;
    }
    .tooltip-container:hover .tooltip-icon {
        transform: scale(1.15);
    }
    .tooltip-popup {
        visibility: hidden;
        opacity: 0;
        width: max-content;
        max-width: 320px;
        background: #0b1728;
        color: #f1f5f9;
        text-align: left;
        border-radius: 8px;
        padding: 10px 14px;
        border: 1px solid #38bdf8;
        box-shadow: 0 10px 28px rgba(0, 0, 0, 0.75);
        font-size: 12px;
        font-weight: 500;
        line-height: 1.5;
        position: absolute;
        z-index: 99999;
        bottom: 135%;
        left: 50%;
        transform: translateX(-50%);
        transition: opacity 0.22s ease-in-out, visibility 0.22s ease-in-out;
        pointer-events: none;
    }
    .tooltip-popup::after {
        content: "";
        position: absolute;
        top: 100%;
        left: 50%;
        margin-left: -6px;
        border-width: 6px;
        border-style: solid;
        border-color: #38bdf8 transparent transparent transparent;
    }
    .tooltip-container:hover .tooltip-popup {
        visibility: visible;
        opacity: 1;
    }

    /* =================================================== */
    /* 🎯 심층 분석 전용 화면 이동 버튼 (왼쪽 카드와 세로 높이 86px 완벽 일치) */
    /* =================================================== */
    .st-key-btn_jump_killchain {
        margin-top: 10px !important;
    }
    .st-key-btn_jump_killchain button {
        height: 86px !important;
        min-height: 86px !important;
        font-size: 15px !important;
        font-weight: 700 !important;
        border-radius: 10px !important;
        background: linear-gradient(135deg, #1e3a8a 0%, #1e40af 100%) !important;
        border: 1.5px solid #38bdf8 !important;
        color: #ffffff !important;
        box-shadow: 0 4px 14px rgba(37, 99, 235, 0.35) !important;
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
        padding: 10px 18px !important;
        line-height: 1.4 !important;
        text-align: center !important;
        white-space: normal !important;
        box-sizing: border-box !important;
        transition: all 0.2s ease-in-out !important;
    }
    .st-key-btn_jump_killchain button:hover {
        background: linear-gradient(135deg, #2563eb 0%, #0284c7 100%) !important;
        border-color: #7dd3fc !important;
        box-shadow: 0 6px 20px rgba(56, 189, 248, 0.55) !important;
        transform: translateY(-2px) !important;
    }
    .st-key-btn_jump_killchain button p {
        font-size: 15px !important;
        font-weight: 700 !important;
        color: #ffffff !important;
        margin: 0 !important;
    }

    /* =================================================== */
    /* 🌟 섀도우 AI 거버넌스 액션 버튼 스타일 (균등 높이 & 시인성 최적화 컬러링) */
    /* =================================================== */
    div[class*="st-key-app_"] button,
    div[class*="st-key-guide_"] button,
    div[class*="st-key-blk_"] button {
        height: 44px !important;
        min-height: 44px !important;
        border-radius: 9px !important;
        font-size: 13.5px !important;
        font-weight: 700 !important;
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
        transition: all 0.2s ease-in-out !important;
        box-sizing: border-box !important;
    }
    /* 정식 승인(양성화): 문구 시인성을 완벽히 유지하는 세련된 에메랄드 그린 배경 */
    div[class*="st-key-app_"] button {
        background: linear-gradient(135deg, rgba(16, 185, 129, 0.28) 0%, rgba(5, 150, 105, 0.42) 100%) !important;
        border: 1.5px solid #10b981 !important;
        color: #ffffff !important;
        box-shadow: 0 2px 10px rgba(16, 185, 129, 0.22) !important;
    }
    div[class*="st-key-app_"] button:hover {
        background: linear-gradient(135deg, rgba(16, 185, 129, 0.50) 0%, rgba(5, 150, 105, 0.68) 100%) !important;
        border-color: #34d399 !important;
        box-shadow: 0 4px 16px rgba(16, 185, 129, 0.45) !important;
        transform: translateY(-2px) !important;
    }
    div[class*="st-key-app_"] button p {
        color: #ffffff !important;
        font-weight: 700 !important;
    }
    /* 사내 프라이빗 도구 안내(Slack) */
    div[class*="st-key-guide_"] button {
        background: #111e33 !important;
        border: 1px solid #2a4365 !important;
        color: #f1f5f9 !important;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3) !important;
    }
    div[class*="st-key-guide_"] button:hover {
        background: #1a3154 !important;
        border-color: #38bdf8 !important;
        color: #38bdf8 !important;
        box-shadow: 0 4px 14px rgba(56, 189, 248, 0.3) !important;
        transform: translateY(-2px) !important;
    }
    div[class*="st-key-guide_"] button p {
        color: #f1f5f9 !important;
        font-weight: 600 !important;
    }
    /* 도메인 차단 룰 생성: 문구 시인성을 완벽히 유지하는 세련된 크림슨 레드 배경 */
    div[class*="st-key-blk_"] button {
        background: linear-gradient(135deg, rgba(239, 68, 68, 0.28) 0%, rgba(185, 28, 28, 0.42) 100%) !important;
        border: 1.5px solid #ef4444 !important;
        color: #ffffff !important;
        box-shadow: 0 2px 10px rgba(239, 68, 68, 0.22) !important;
    }
    div[class*="st-key-blk_"] button:hover {
        background: linear-gradient(135deg, rgba(239, 68, 68, 0.50) 0%, rgba(185, 28, 28, 0.68) 100%) !important;
        border-color: #f87171 !important;
        box-shadow: 0 4px 16px rgba(239, 68, 68, 0.45) !important;
        transform: translateY(-2px) !important;
    }
    div[class*="st-key-blk_"] button p {
        color: #ffffff !important;
        font-weight: 700 !important;
    }
</style>
""", unsafe_allow_html=True)

# 3. 툴팁 헬퍼 함수
def tooltip(icon: str, title: str, desc: str) -> str:
    """아이콘 호버 시 세련된 사이버펑크 툴팁 팝업 렌더링"""
    return f"""
    <span class="tooltip-container">
        <span class="tooltip-icon">{icon}</span>
        <span class="tooltip-popup">
            <b style="color:#38bdf8; font-size:13px;">{title}</b><br>
            <span style="color:#cbd5e1;">{desc}</span>
        </span>
    </span>
    """

# 4. 데이터 컨텍스트 캐싱 (Streamlit Cloud 연산 딜레이 방지)
@st.cache_resource
def get_cached_context():
    return get_context()

ctx = get_cached_context()
incidents = ctx.correlation_engine.get_all_incidents()
shadow_assets = ctx.governance_engine.get_all_assets()

# 전역 인시던트 목록 및 세션 상태 초기화
incident_ids = [inc.incident_id for inc in incidents]
if "selected_incident_id" not in st.session_state:
    st.session_state.selected_incident_id = incident_ids[0]
if "nav_radio" not in st.session_state:
    st.session_state.nav_radio = "대시보드 종합 관제"

# 안전한 페이지 전환 및 인시던트 선택 콜백 (StreamlitAPIException 방지)
def navigate_to(page_name, inc_id=None):
    st.session_state.nav_radio = page_name
    if inc_id:
        st.session_state.selected_incident_id = inc_id

def select_incident_cb(inc_id):
    st.session_state.selected_incident_id = inc_id

# 5. 사이드바 구성
with st.sidebar:
    st.markdown(f"""
    <div style="padding: 10px 0 20px 0;">
        <h2 style="color: #f5f7fb; margin:0; font-size:22px; font-weight:700;">
            {tooltip("🛡️", "NexusGuard XDR Platform", "이기종 다차원 로그 상관분석 & 섀도우 AI 거버넌스 자동화 시스템")} NexusGuard
        </h2>
        <span style="color: #9fb0c8; font-size:13px;">Zero Trust XDR & Shadow AI</span>
    </div>
    """, unsafe_allow_html=True)

    menu_options = ["대시보드 종합 관제", "침해사고 킬체인 분석", "섀도우 AI·IT 거버넌스", "Zero Trust 승인센터", "원천 이벤트 탐색"]
    if "nav_radio" not in st.session_state:
        st.session_state.nav_radio = "대시보드 종합 관제"

    menu = st.radio(
        "네비게이션",
        menu_options,
        key="nav_radio",
        label_visibility="collapsed"
    )

    st.markdown("---")
    with st.expander("🧪 2단계 상태머신 실시간 시뮬레이터", expanded=True):
        st.markdown("<div style='font-size:12px; color:#cbd5e1; margin-bottom:10px;'>사내 Shadow AI 기밀 유출 킬체인을 단계별로 실시간 시뮬레이션합니다.</div>", unsafe_allow_html=True)
        col_s1, col_s2 = st.columns(2)
        with col_s1:
            btn_watch = st.button("👁️ 1단계\n선제감시(WATCH)", use_container_width=True, help="기밀 DB 조회 + 미승인 AI 질의 발생 -> 전송 전 WATCH 상태 승격")
        with col_s2:
            btn_high = st.button("🚨 2단계\n유출확정(HIGH)", use_container_width=True, help="WATCH 대상자의 48MB 대용량 외부 전송 발생 -> HIGH Incident 즉시 확정")
            
        col_s3, col_s4 = st.columns(2)
        with col_s3:
            btn_heal = st.button("⏱️ 30분 만료\n(오탐 자동 해제)", use_container_width=True, help="전송 없이 30분 경과 -> NORMAL 상태로 자가 치유")
        with col_s4:
            btn_reset = st.button("🔄 시뮬 리셋", use_container_width=True, help="시뮬레이션 데이터 초기화")

    if btn_watch:
        now = datetime.utcnow()
        ev1 = SecurityEvent(
            event_id=f"EVT-SIM-DB-{int(now.timestamp())}",
            timestamp=now,
            log_source=LogSource.DB,
            actor=Actor(user_id="park_finance", src_ip="192.168.10.77"),
            target=Target(dst_ip="10.0.0.30", dst_port=3306),
            action=EventAction.SELECT,
            payload=PayloadMetadata(table_name="customer_vault", query_string="SELECT user_id, rrn, balance FROM customer_vault")
        )
        ev2 = SecurityEvent(
            event_id=f"EVT-SIM-DNS-{int(now.timestamp())}",
            timestamp=now + timedelta(seconds=5),
            log_source=LogSource.DNS,
            actor=Actor(user_id="park_finance", src_ip="192.168.10.77"),
            target=Target(domain="chatgpt.com"),
            action=EventAction.QUERY,
            payload=PayloadMetadata(category="Generative_AI")
        )
        ctx.correlation_engine.update_user_risk(ev1)
        ctx.correlation_engine.update_user_risk(ev2)
        st.toast("⚡ [1단계 선제 감시] 사용자 'park_finance'가 WATCH 상태로 승격되었습니다!", icon="👁️")
        st.rerun()

    if btn_high:
        now = datetime.utcnow()
        ev3 = SecurityEvent(
            event_id=f"EVT-SIM-FW-{int(now.timestamp())}",
            timestamp=now,
            log_source=LogSource.FIREWALL,
            actor=Actor(user_id="park_finance", src_ip="192.168.10.77"),
            target=Target(domain="api.openai.com", dst_port=443),
            action=EventAction.ALLOW,
            payload=PayloadMetadata(bytes_sent=48500000)
        )
        ctx.correlation_engine.update_user_risk(ev3)
        for inc in ctx.correlation_engine.get_all_incidents():
            if "park_finance" in inc.title or "park_finance" in inc.actor:
                st.session_state.selected_incident_id = inc.incident_id
                break
        st.toast("🚨 [2단계 유출 확정] 'park_finance' 외부 48.5MB 전송 포착! HIGH Incident 생성 완료!", icon="🚨")
        st.rerun()

    if btn_heal:
        now = datetime.utcnow()
        ctx.correlation_engine.store.upsert_risk(
            user="choi_intern",
            state="NORMAL",
            score=15,
            reasons=["30분 경과: 외부 데이터 전송 행위 없음 (오탐 자동 해제)"],
            expires_at=now + timedelta(hours=1)
        )
        ctx.correlation_engine.store.append_history(
            user="choi_intern",
            from_state="WATCH",
            to_state="NORMAL",
            reason="30분 만료(TTL)로 인한 정상(NORMAL) 자가 치유"
        )
        st.toast("⏱️ [오탐 자동 해제] 30분간 전송이 없었던 'choi_intern'이 NORMAL로 자가 치유되었습니다.", icon="⏱️")
        st.rerun()

    if btn_reset:
        with ctx.correlation_engine.store._get_conn() as conn:
            conn.execute("DELETE FROM user_risk WHERE user IN ('park_finance', 'choi_intern')")
            conn.execute("DELETE FROM risk_history WHERE user IN ('park_finance', 'choi_intern')")
            conn.execute("DELETE FROM incidents WHERE actor LIKE '%park_finance%'")
            conn.commit()
        remove_keys = [k for k, inc in list(ctx.correlation_engine.incidents.items()) if "park_finance" in inc.actor]
        for k in remove_keys:
            del ctx.correlation_engine.incidents[k]
        st.toast("🔄 시뮬레이션 상태가 리셋되었습니다.", icon="🔄")
        st.rerun()

    st.markdown("---")
    st.markdown(f"""
    <div style="background: #111e30; padding: 14px; border-radius: 10px; border: 1px solid #1e3352;">
        <span style="font-size:12px; font-weight:700; color:#9fb0c8;">
            {tooltip("⚙️", "시스템 데몬 상태", "백그라운드에서 실행 중인 4대 핵심 파이프라인 데몬의 헬스체크 상태입니다.")} 파이프라인 상태 모니터링
        </span>
        <div style="color: #62d487; font-size:12px; margin-top:8px;">
            {tooltip("●", "DNS 수집기 (dnsmasq)", "사내 DNS 서버로부터 실시간 도메인 질의 로그를 무중단 수집 중")} DNS 수집기 (dnsmasq) 정상
        </div>
        <div style="color: #62d487; font-size:12px; margin-top:4px;">
            {tooltip("●", "통합 정규화 파서", "Auth, FW, DB, Web 로그를 단일 표준 JSON으로 정규화 변환 중")} 이기종 로그 정규화 정상
        </div>
        <div style="color: #62d487; font-size:12px; margin-top:4px;">
            {tooltip("●", "상관분석 엔진", "슬라이딩 윈도우 기반 킬체인 및 데이터 유출 시퀀스 실시간 연산 중")} 듀얼 상관분석 엔진 가동 중
        </div>
        <div style="color: #62d487; font-size:12px; margin-top:4px;">
            {tooltip("●", "Gemini AI 모듈", "미등록 도메인 식별 및 데이터 재학습 위험도 진단 대기 중")} Gemini AI 판별 모듈 대기
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("<br><div style='color:#566981; font-size:11px; text-align:center;'>SKT ALEPH 캡스톤 4조 NexusGuard v1.0</div>", unsafe_allow_html=True)


# ==========================================
# VIEW 1: 대시보드 종합 관제 (Overview)
# ==========================================
# 동적 SVG 생성 (가로 900px 와이드 뷰박스 지원 및 모든 인시던트별 맞춤형 고품질 토폴로지)
def generate_dynamic_network_svg(inc: Incident) -> str:
    cid = inc.incident_id

    # 공통 SVG 그라데이션 및 필터 정의
    svg_defs = """
            <defs>
                <linearGradient id="grad-attacker" x1="0" y1="0" x2="1" y2="1">
                    <stop offset="0%" stop-color="#1e3a8a"/>
                    <stop offset="100%" stop-color="#0f172a"/>
                </linearGradient>
                <linearGradient id="grad-node" x1="0" y1="0" x2="1" y2="1">
                    <stop offset="0%" stop-color="#1e293b"/>
                    <stop offset="100%" stop-color="#0f172a"/>
                </linearGradient>
            </defs>
    """

    # 1. INC-001: 금융 고객 개인정보 2.4만 건 대량 탈취 및 C2 비정상 유출
    if cid == "INC-001":
        return f"""
        <svg width="100%" height="240" viewBox="0 0 900 240" xmlns="http://www.w3.org/2000/svg">
            {svg_defs}
            <!-- Node 1: Attacker / Internet C2 -->
            <circle cx="90" cy="125" r="54" fill="url(#grad-attacker)" stroke="#ef4444" stroke-width="2.5"/>
            <text x="90" y="110" fill="#ffffff" font-size="12" font-weight="bold" text-anchor="middle">Internet / C2</text>
            <text x="90" y="128" fill="#93c5fd" font-size="10" text-anchor="middle">203.116.45.23</text>
            <text x="90" y="146" fill="#ff8591" font-size="10" font-weight="bold" text-anchor="middle">[공격 발원 및 탈취]</text>

            <!-- Node 2: Web Server -->
            <rect x="245" y="85" width="130" height="80" rx="10" fill="url(#grad-node)" stroke="#ef4444" stroke-width="2.5"/>
            <text x="310" y="112" fill="#ffffff" font-size="12" font-weight="bold" text-anchor="middle">DMZ 웹서버</text>
            <text x="310" y="130" fill="#f87171" font-size="10" text-anchor="middle">10.0.0.10:443</text>
            <text x="310" y="148" fill="#ff7b88" font-size="10" text-anchor="middle">[웹쉘 / 최초 침투]</text>

            <!-- Node 3: Internal Server -->
            <rect x="465" y="85" width="130" height="80" rx="10" fill="url(#grad-node)" stroke="#f59e0b" stroke-width="2.5"/>
            <text x="530" y="112" fill="#ffffff" font-size="12" font-weight="bold" text-anchor="middle">내부 경유 서버</text>
            <text x="530" y="130" fill="#fbbf24" font-size="10" text-anchor="middle">10.0.0.20:22</text>
            <text x="530" y="148" fill="#ffd169" font-size="10" text-anchor="middle">[SSH 측면 이동]</text>

            <!-- Node 4: DB Server -->
            <rect x="685" y="85" width="145" height="80" rx="10" fill="url(#grad-node)" stroke="#ef4444" stroke-width="2.5"/>
            <text x="757" y="112" fill="#ffffff" font-size="12" font-weight="bold" text-anchor="middle">고객 Core DB</text>
            <text x="757" y="130" fill="#f87171" font-size="10" text-anchor="middle">10.0.0.30:3306</text>
            <text x="757" y="148" fill="#ff7b88" font-size="10" font-weight="bold" text-anchor="middle">[고객 2.4만건 덤프]</text>

            <!-- Connectors -->
            <line x1="144" y1="125" x2="245" y2="125" stroke="#ef4444" stroke-width="3" stroke-dasharray="6,3"/>
            <text x="195" y="112" fill="#ff7b88" font-size="10" font-weight="bold" text-anchor="middle">:443 웹 취약점</text>

            <line x1="375" y1="125" x2="465" y2="125" stroke="#f59e0b" stroke-width="3"/>
            <text x="420" y="112" fill="#fbbf24" font-size="10" font-weight="bold" text-anchor="middle">:22 SSH</text>

            <line x1="595" y1="125" x2="685" y2="125" stroke="#ef4444" stroke-width="3"/>
            <text x="640" y="112" fill="#ff7b88" font-size="10" font-weight="bold" text-anchor="middle">:3306 쿼리 탈취</text>

            <!-- C2 Leak Arc -->
            <path d="M 757 85 Q 425 25, 90 71" fill="none" stroke="#ef4444" stroke-width="2.5" stroke-dasharray="6,3"/>
            <text x="425" y="24" fill="#ff8591" font-size="11" font-weight="bold" text-anchor="middle">⚠️ C2 대량 비정상 데이터 유출 통로 (:10443 / 158 MB)</text>
        </svg>
        """

    # 2. INC-002: 마케팅팀 미승인 생성형 AI(ChatGPT)를 통한 신규 전략기획서 유출 의심
    elif cid == "INC-002":
        return f"""
        <svg width="100%" height="240" viewBox="0 0 900 240" xmlns="http://www.w3.org/2000/svg">
            {svg_defs}
            <!-- Node 1: Marketing PC -->
            <rect x="70" y="85" width="130" height="70" rx="10" fill="url(#grad-node)" stroke="#38bdf8" stroke-width="2.5"/>
            <text x="135" y="116" fill="#ffffff" font-size="13" font-weight="bold" text-anchor="middle">마케팅팀 PC</text>
            <text x="135" y="136" fill="#93c5fd" font-size="10" text-anchor="middle">192.168.10.45</text>
            <text x="135" y="174" fill="#64748b" font-size="10" text-anchor="middle">[유출 발원 단말]</text>

            <!-- Node 2: Core DB -->
            <rect x="370" y="30" width="140" height="65" rx="10" fill="url(#grad-node)" stroke="#f59e0b" stroke-width="2.5"/>
            <text x="440" y="60" fill="#ffffff" font-size="12" font-weight="bold" text-anchor="middle">사내 DB (10.0.0.30)</text>
            <text x="440" y="80" fill="#fbbf24" font-size="10" text-anchor="middle">전략기획서 SELECT</text>

            <!-- Node 3: DNS Server -->
            <rect x="370" y="145" width="140" height="65" rx="10" fill="url(#grad-node)" stroke="#10b981" stroke-width="2.5"/>
            <text x="440" y="175" fill="#ffffff" font-size="12" font-weight="bold" text-anchor="middle">DNS 리졸버 (:53)</text>
            <text x="440" y="195" fill="#6ee7b7" font-size="10" text-anchor="middle">chatgpt.com 질의 포착</text>

            <!-- Node 4: OpenAI Cloud -->
            <circle cx="760" cy="120" r="58" fill="#450a0a" stroke="#ef4444" stroke-width="2.5"/>
            <text x="760" y="104" fill="#ffffff" font-size="13" font-weight="bold" text-anchor="middle">OpenAI Cloud</text>
            <text x="760" y="122" fill="#fca5a5" font-size="10" text-anchor="middle">api.openai.com</text>
            <text x="760" y="142" fill="#ff7b88" font-size="10" font-weight="bold" text-anchor="middle">[1.45 MB 기밀 유출]</text>

            <!-- Connectors -->
            <line x1="200" y1="105" x2="370" y2="62" stroke="#f59e0b" stroke-width="2.5"/>
            <line x1="200" y1="135" x2="370" y2="175" stroke="#10b981" stroke-width="2.5"/>
            <line x1="510" y1="175" x2="706" y2="134" stroke="#ef4444" stroke-width="3" stroke-dasharray="6,3"/>
            <text x="608" y="140" fill="#ff8591" font-size="11" font-weight="bold" text-anchor="middle" transform="rotate(-11.8, 608, 140)">REST POST 프롬프트 전송</text>
        </svg>
        """

    # 3. INC-003: 제조 공정망(OT) 랜섬웨어 선행 단계 비인가 RDP 접속 및 볼륨 섀도우 삭제
    elif cid == "INC-003":
        return f"""
        <svg width="100%" height="240" viewBox="0 0 900 240" xmlns="http://www.w3.org/2000/svg">
            {svg_defs}
            <!-- Node 1: Infected Host -->
            <rect x="60" y="80" width="145" height="80" rx="10" fill="#450a0a" stroke="#ef4444" stroke-width="2.5"/>
            <text x="132" y="107" fill="#ffffff" font-size="12" font-weight="bold" text-anchor="middle">감염 단말 (공정 PC)</text>
            <text x="132" y="125" fill="#fca5a5" font-size="10" text-anchor="middle">172.16.50.88</text>
            <text x="132" y="143" fill="#ff7b88" font-size="10" text-anchor="middle">[피싱 악성코드 실행]</text>

            <!-- Node 2: SCADA Gateway -->
            <rect x="330" y="80" width="150" height="80" rx="10" fill="url(#grad-node)" stroke="#f59e0b" stroke-width="2.5"/>
            <text x="405" y="107" fill="#ffffff" font-size="12" font-weight="bold" text-anchor="middle">SCADA GW (:3389)</text>
            <text x="405" y="125" fill="#fbbf24" font-size="10" text-anchor="middle">172.16.50.1</text>
            <text x="405" y="143" fill="#ffd169" font-size="10" text-anchor="middle">[RDP 브루트포스 돌파]</text>

            <!-- Node 3: Backup NAS -->
            <rect x="650" y="25" width="160" height="75" rx="10" fill="#450a0a" stroke="#dc2626" stroke-width="2.5"/>
            <text x="730" y="52" fill="#ffffff" font-size="12" font-weight="bold" text-anchor="middle">백업 NAS (:445)</text>
            <text x="730" y="70" fill="#fca5a5" font-size="10" text-anchor="middle">172.16.50.250</text>
            <text x="730" y="88" fill="#ff7b88" font-size="10" font-weight="bold" text-anchor="middle">[볼륨 섀도우 복사본 파괴]</text>

            <!-- Node 4: OT PLC -->
            <circle cx="730" cy="175" r="50" fill="#3b0764" stroke="#a855f7" stroke-width="2.5"/>
            <text x="730" y="162" fill="#ffffff" font-size="12" font-weight="bold" text-anchor="middle">공정 제어망 PLC</text>
            <text x="730" y="178" fill="#d8b4fe" font-size="10" text-anchor="middle">172.16.50.100</text>
            <text x="730" y="195" fill="#ff7b88" font-size="9" font-weight="bold" text-anchor="middle">[라인 가동 중단 위협]</text>

            <!-- Connectors -->
            <line x1="205" y1="120" x2="330" y2="120" stroke="#ef4444" stroke-width="3" stroke-dasharray="6,3"/>
            <text x="267" y="108" fill="#ff7b88" font-size="10" font-weight="bold" text-anchor="middle">RDP 세션 강제 체결</text>

            <line x1="480" y1="100" x2="650" y2="62" stroke="#dc2626" stroke-width="3.5"/>
            <text x="565" y="70" fill="#ef4444" font-size="10" font-weight="bold" text-anchor="middle" transform="rotate(-12.6, 565, 70)">vssadmin 섀도우 파괴</text>

            <line x1="480" y1="140" x2="680" y2="175" stroke="#a855f7" stroke-width="3" stroke-dasharray="5,3"/>
            <text x="580" y="146" fill="#c084fc" font-size="10" font-weight="bold" text-anchor="middle" transform="rotate(9.9, 580, 146)">⚠️ OT 제어망 침해 위협</text>
        </svg>
        """

    # 4. INC-004: 사내 SSL-VPN 인증 정보 탈취 후 Tor 출구 노드 경유 관리자 API 대량 호출
    elif cid == "INC-004":
        return f"""
        <svg width="100%" height="240" viewBox="0 0 900 240" xmlns="http://www.w3.org/2000/svg">
            {svg_defs}
            <!-- Node 1: Tor Network -->
            <circle cx="110" cy="120" r="58" fill="#2e1065" stroke="#a855f7" stroke-width="2.5"/>
            <text x="110" y="104" fill="#ffffff" font-size="12" font-weight="bold" text-anchor="middle">Tor 다중 출구 노드</text>
            <text x="110" y="122" fill="#d8b4fe" font-size="10" text-anchor="middle">185.220.101.5</text>
            <text x="110" y="142" fill="#fca5a5" font-size="10" font-weight="bold" text-anchor="middle">[32개국 우회 접근]</text>

            <!-- Node 2: VPN Gateway -->
            <rect x="340" y="80" width="160" height="80" rx="10" fill="url(#grad-node)" stroke="#ef4444" stroke-width="2.5"/>
            <text x="420" y="107" fill="#ffffff" font-size="12" font-weight="bold" text-anchor="middle">사내 SSL-VPN</text>
            <text x="420" y="125" fill="#f87171" font-size="10" text-anchor="middle">10.0.0.1:443</text>
            <text x="420" y="143" fill="#ff7b88" font-size="10" text-anchor="middle">[탈취 계정(park_infra)]</text>

            <!-- Node 3: IAM Admin Console -->
            <circle cx="750" cy="120" r="58" fill="#450a0a" stroke="#ef4444" stroke-width="2.5"/>
            <text x="750" y="104" fill="#ffffff" font-size="12" font-weight="bold" text-anchor="middle">IAM 관리자 콘솔</text>
            <text x="750" y="122" fill="#fca5a5" font-size="10" text-anchor="middle">10.0.0.8:8443</text>
            <text x="750" y="142" fill="#ff7b88" font-size="10" font-weight="bold" text-anchor="middle">[전 직원 계정 덤프]</text>

            <!-- Connectors -->
            <line x1="168" y1="120" x2="340" y2="120" stroke="#ef4444" stroke-width="3" stroke-dasharray="6,3"/>
            <text x="254" y="108" fill="#ff7b88" font-size="11" font-weight="bold" text-anchor="middle">불가능한 이동거리 로그인</text>

            <line x1="500" y1="120" x2="692" y2="120" stroke="#ef4444" stroke-width="3.5"/>
            <text x="596" y="108" fill="#ff8591" font-size="11" font-weight="bold" text-anchor="middle">⚠️ 비인가 /users/export API 호출</text>
        </svg>
        """

    # 5. INC-005: 개발자 GitHub 저장소 AWS IAM Key 노출 및 S3 비정상 대량 다운로드
    elif cid == "INC-005":
        return f"""
        <svg width="100%" height="240" viewBox="0 0 900 240" xmlns="http://www.w3.org/2000/svg">
            {svg_defs}
            <!-- Node 1: Developer PC -->
            <rect x="60" y="25" width="145" height="75" rx="10" fill="url(#grad-node)" stroke="#38bdf8" stroke-width="2.5"/>
            <text x="132" y="52" fill="#ffffff" font-size="12" font-weight="bold" text-anchor="middle">개발자 단말</text>
            <text x="132" y="70" fill="#93c5fd" font-size="10" text-anchor="middle">192.168.20.15</text>
            <text x="132" y="88" fill="#64748b" font-size="9" text-anchor="middle">[Access Key 커밋]</text>

            <!-- Node 2: GitHub Public -->
            <circle cx="430" cy="62" r="56" fill="#1c1917" stroke="#f59e0b" stroke-width="2.5"/>
            <text x="430" y="48" fill="#ffffff" font-size="12" font-weight="bold" text-anchor="middle">GitHub Public</text>
            <text x="430" y="65" fill="#fbbf24" font-size="10" text-anchor="middle">AKIA_DEV_SYNC</text>
            <text x="430" y="83" fill="#fca5a5" font-size="10" font-weight="bold" text-anchor="middle">[퍼블릭 시크릿 노출]</text>

            <!-- Node 3: Attacker AWS Region -->
            <rect x="60" y="140" width="145" height="75" rx="10" fill="#450a0a" stroke="#ef4444" stroke-width="2.5"/>
            <text x="132" y="167" fill="#ffffff" font-size="12" font-weight="bold" text-anchor="middle">해외 공격자 IP</text>
            <text x="132" y="185" fill="#fca5a5" font-size="10" text-anchor="middle">54.239.28.12</text>
            <text x="132" y="203" fill="#ff7b88" font-size="9" text-anchor="middle">[유출 키 악용 탐지]</text>

            <!-- Node 4: AWS S3 Bucket -->
            <circle cx="760" cy="120" r="58" fill="#450a0a" stroke="#ef4444" stroke-width="2.5"/>
            <text x="760" y="104" fill="#ffffff" font-size="12" font-weight="bold" text-anchor="middle">AWS S3 버킷</text>
            <text x="760" y="122" fill="#fca5a5" font-size="10" text-anchor="middle">corp-analytics-prod</text>
            <text x="760" y="142" fill="#ff7b88" font-size="10" font-weight="bold" text-anchor="middle">[82GB 비식별화 전 덤프]</text>

            <!-- Connectors -->
            <line x1="205" y1="62" x2="374" y2="62" stroke="#38bdf8" stroke-width="2.5"/>
            <text x="289" y="50" fill="#38bdf8" font-size="10" font-weight="bold" text-anchor="middle">git push 시크릿 노출</text>

            <line x1="486" y1="65" x2="705" y2="105" stroke="#f59e0b" stroke-width="2.5"/>
            <text x="595" y="74" fill="#fbbf24" font-size="10" font-weight="bold" text-anchor="middle" transform="rotate(10.3, 595, 74)">IAM 토큰 검증 통과</text>

            <line x1="205" y1="175" x2="705" y2="135" stroke="#ef4444" stroke-width="3" stroke-dasharray="6,3"/>
            <text x="455" y="137" fill="#ff8591" font-size="11" font-weight="bold" text-anchor="middle" transform="rotate(-4.6, 455, 137)">⚠️ GetObject API 12,000회 대량 다운로드 (:443)</text>
        </svg>
        """

    # 6. INC-006: 사내 그룹웨어 Log4j 취약점(CVE-2021-44228) 악용 웹쉘 업로드 및 비콘 통신
    elif cid == "INC-006":
        return f"""
        <svg width="100%" height="240" viewBox="0 0 900 240" xmlns="http://www.w3.org/2000/svg">
            {svg_defs}
            <!-- Node 1: Cobalt Strike C2 -->
            <circle cx="110" cy="120" r="58" fill="#450a0a" stroke="#ef4444" stroke-width="2.5"/>
            <text x="110" y="104" fill="#ffffff" font-size="12" font-weight="bold" text-anchor="middle">Cobalt Strike C2</text>
            <text x="110" y="122" fill="#fca5a5" font-size="10" text-anchor="middle">103.145.13.91</text>
            <text x="110" y="142" fill="#ff7b88" font-size="10" font-weight="bold" text-anchor="middle">[30s 주기 비콘 수신]</text>

            <!-- Node 2: Groupware Server -->
            <rect x="350" y="80" width="160" height="80" rx="10" fill="url(#grad-node)" stroke="#ef4444" stroke-width="2.5"/>
            <text x="430" y="107" fill="#ffffff" font-size="12" font-weight="bold" text-anchor="middle">사내 그룹웨어</text>
            <text x="430" y="125" fill="#f87171" font-size="10" text-anchor="middle">10.0.0.15:8080</text>
            <text x="430" y="143" fill="#ff7b88" font-size="10" text-anchor="middle">[/upload/shell.jsp 웹쉘]</text>

            <!-- Node 3: Malicious LDAP Server -->
            <circle cx="750" cy="120" r="58" fill="#2e1065" stroke="#dc2626" stroke-width="2.5"/>
            <text x="750" y="104" fill="#ffffff" font-size="12" font-weight="bold" text-anchor="middle">악성 LDAP 서버</text>
            <text x="750" y="122" fill="#d8b4fe" font-size="10" text-anchor="middle">103.145.13.91:1389</text>
            <text x="750" y="142" fill="#fca5a5" font-size="10" font-weight="bold" text-anchor="middle">[원격 클래스 인젝션]</text>

            <!-- Connectors -->
            <line x1="168" y1="120" x2="350" y2="120" stroke="#ef4444" stroke-width="3" stroke-dasharray="6,3"/>
            <text x="259" y="108" fill="#ff7b88" font-size="10" font-weight="bold" text-anchor="middle">Log4j JNDI 인젝션</text>

            <line x1="510" y1="120" x2="692" y2="120" stroke="#dc2626" stroke-width="3"/>
            <text x="601" y="108" fill="#fca5a5" font-size="10" font-weight="bold" text-anchor="middle">ldap:// 악성 페이로드 로딩</text>

            <!-- Beacon Arc -->
            <path d="M 430 80 Q 270 36, 110 65" fill="none" stroke="#ef4444" stroke-width="2.5" stroke-dasharray="6,3"/>
            <text x="270" y="24" fill="#ff8591" font-size="11" font-weight="bold" text-anchor="middle">⚠️ 30초 주기 은닉 비콘 하트비트 (:443)</text>
        </svg>
        """

    # 7. INC-007: 퇴사 예정 연구원의 대용량 WeTransfer 익명 전송을 통한 핵심 소스코드 반출 시도
    elif cid == "INC-007":
        return f"""
        <svg width="100%" height="240" viewBox="0 0 900 240" xmlns="http://www.w3.org/2000/svg">
            {svg_defs}
            <!-- Node 1: Research PC -->
            <rect x="70" y="85" width="130" height="70" rx="10" fill="url(#grad-node)" stroke="#38bdf8" stroke-width="2.5"/>
            <text x="135" y="112" fill="#ffffff" font-size="12" font-weight="bold" text-anchor="middle">연구원 단말</text>
            <text x="135" y="130" fill="#93c5fd" font-size="10" text-anchor="middle">192.168.30.12</text>
            <text x="135" y="148" fill="#64748b" font-size="10" text-anchor="middle">[퇴사 예정자]</text>

            <!-- Node 2: GitLab Server -->
            <rect x="370" y="30" width="140" height="65" rx="10" fill="url(#grad-node)" stroke="#f59e0b" stroke-width="2.5"/>
            <text x="440" y="57" fill="#ffffff" font-size="12" font-weight="bold" text-anchor="middle">사내 GitLab (10.0.0.25)</text>
            <text x="440" y="75" fill="#fbbf24" font-size="10" text-anchor="middle">repo_core_algo.zip</text>
            <text x="440" y="88" fill="#ffd169" font-size="9" text-anchor="middle">[알고리즘 덤프]</text>

            <!-- Node 3: DNS Server -->
            <rect x="370" y="145" width="140" height="65" rx="10" fill="url(#grad-node)" stroke="#10b981" stroke-width="2.5"/>
            <text x="440" y="172" fill="#ffffff" font-size="12" font-weight="bold" text-anchor="middle">DNS 리졸버 (:53)</text>
            <text x="440" y="190" fill="#6ee7b7" font-size="10" text-anchor="middle">wetransfer.com 질의</text>
            <text x="440" y="203" fill="#a7f3d0" font-size="9" text-anchor="middle">[비인가 SaaS 탐지]</text>

            <!-- Node 4: WeTransfer Cloud -->
            <circle cx="760" cy="120" r="58" fill="#451a03" stroke="#f59e0b" stroke-width="2.5"/>
            <text x="760" y="104" fill="#ffffff" font-size="12" font-weight="bold" text-anchor="middle">WeTransfer Cloud</text>
            <text x="760" y="122" fill="#fca5a5" font-size="10" text-anchor="middle">wetransfer.com</text>
            <text x="760" y="142" fill="#ff7b88" font-size="10" font-weight="bold" text-anchor="middle">[420MB 업로드 차단]</text>

            <!-- Connectors -->
            <line x1="200" y1="105" x2="370" y2="62" stroke="#f59e0b" stroke-width="2.5"/>
            <text x="285" y="72" fill="#fbbf24" font-size="10" font-weight="bold" text-anchor="middle" transform="rotate(-14.2, 285, 72)">zip 일괄 아카이빙</text>

            <line x1="200" y1="135" x2="370" y2="175" stroke="#10b981" stroke-width="2.5"/>
            <text x="285" y="146" fill="#6ee7b7" font-size="10" font-weight="bold" text-anchor="middle" transform="rotate(13.2, 285, 146)">비인가 SaaS 질의</text>

            <line x1="510" y1="175" x2="706" y2="134" stroke="#ef4444" stroke-width="3" stroke-dasharray="6,3"/>
            <text x="608" y="140" fill="#ff8591" font-size="11" font-weight="bold" text-anchor="middle" transform="rotate(-11.8, 608, 140)">⚠️ 420 MB 대용량 업로드 (차단)</text>
        </svg>
        """

    # 8. INC-008: 인사평가 위장 피싱 메일 악성 매크로 실행 및 Active Directory(AD) 정찰
    elif cid == "INC-008":
        return f"""
        <svg width="100%" height="240" viewBox="0 0 900 240" xmlns="http://www.w3.org/2000/svg">
            {svg_defs}
            <!-- Node 1: External Mail Server -->
            <circle cx="110" cy="120" r="58" fill="#450a0a" stroke="#ef4444" stroke-width="2.5"/>
            <text x="110" y="104" fill="#ffffff" font-size="12" font-weight="bold" text-anchor="middle">외부 피싱 메일</text>
            <text x="110" y="122" fill="#fca5a5" font-size="10" text-anchor="middle">SPF/DKIM 변조</text>
            <text x="110" y="142" fill="#ff7b88" font-size="10" font-weight="bold" text-anchor="middle">[스피어피싱 발송]</text>

            <!-- Node 2: HR PC -->
            <rect x="350" y="80" width="160" height="80" rx="10" fill="url(#grad-node)" stroke="#ef4444" stroke-width="2.5"/>
            <text x="430" y="107" fill="#ffffff" font-size="12" font-weight="bold" text-anchor="middle">인사팀 단말</text>
            <text x="430" y="125" fill="#f87171" font-size="10" text-anchor="middle">192.168.10.105</text>
            <text x="430" y="143" fill="#ff7b88" font-size="10" text-anchor="middle">[매크로 / PowerShell]</text>

            <!-- Node 3: Active Directory DC -->
            <circle cx="750" cy="120" r="58" fill="#2e1065" stroke="#f59e0b" stroke-width="2.5"/>
            <text x="750" y="104" fill="#ffffff" font-size="12" font-weight="bold" text-anchor="middle">Domain Controller</text>
            <text x="750" y="122" fill="#fbbf24" font-size="10" text-anchor="middle">10.0.0.5:389 LDAP</text>
            <text x="750" y="142" fill="#ffd169" font-size="10" font-weight="bold" text-anchor="middle">[BloodHound 계정 정찰]</text>

            <!-- Connectors -->
            <line x1="168" y1="120" x2="350" y2="120" stroke="#ef4444" stroke-width="3" stroke-dasharray="6,3"/>
            <text x="259" y="108" fill="#ff7b88" font-size="10" font-weight="bold" text-anchor="middle">악성 .xlsm 매크로 유입</text>

            <line x1="510" y1="120" x2="692" y2="120" stroke="#f59e0b" stroke-width="3"/>
            <text x="601" y="108" fill="#fbbf24" font-size="10" font-weight="bold" text-anchor="middle">⚠️ 도메인 관리자 권한 정찰 (:389)</text>
        </svg>
        """

    # 9. INC-009: 사내 유휴 GPU 개발 서버 침투 후 비인가 가상화폐 채굴 구동
    elif cid == "INC-009":
        return f"""
        <svg width="100%" height="240" viewBox="0 0 900 240" xmlns="http://www.w3.org/2000/svg">
            {svg_defs}
            <!-- Node 1: External Attacker -->
            <circle cx="110" cy="120" r="58" fill="#450a0a" stroke="#ef4444" stroke-width="2.5"/>
            <text x="110" y="104" fill="#ffffff" font-size="12" font-weight="bold" text-anchor="middle">외부 침투 공격자</text>
            <text x="110" y="122" fill="#fca5a5" font-size="10" text-anchor="middle">45.142.122.90</text>
            <text x="110" y="142" fill="#ff7b88" font-size="10" font-weight="bold" text-anchor="middle">[Docker API 스캔]</text>

            <!-- Node 2: GPU Dev Server -->
            <rect x="340" y="80" width="170" height="80" rx="10" fill="url(#grad-node)" stroke="#a855f7" stroke-width="2.5"/>
            <text x="425" y="107" fill="#ffffff" font-size="12" font-weight="bold" text-anchor="middle">GPU 개발서버 (RTX 4090)</text>
            <text x="425" y="125" fill="#c084fc" font-size="10" text-anchor="middle">10.0.0.80:2375</text>
            <text x="425" y="143" fill="#e9d5ff" font-size="10" text-anchor="middle">[XMRig 무단 가동 / 99% 부하]</text>

            <!-- Node 3: Mining Pool -->
            <circle cx="750" cy="120" r="58" fill="#451a03" stroke="#f59e0b" stroke-width="2.5"/>
            <text x="750" y="104" fill="#ffffff" font-size="12" font-weight="bold" text-anchor="middle">모네로 채굴 풀</text>
            <text x="750" y="122" fill="#fbbf24" font-size="10" text-anchor="middle">minergate.com:3333</text>
            <text x="750" y="142" fill="#ffd169" font-size="10" font-weight="bold" text-anchor="middle">[해시 파워 무단 반출]</text>

            <!-- Connectors -->
            <line x1="168" y1="120" x2="340" y2="120" stroke="#ef4444" stroke-width="3" stroke-dasharray="6,3"/>
            <text x="254" y="108" fill="#ff7b88" font-size="10" font-weight="bold" text-anchor="middle">:2375 컨테이너 무단 생성</text>

            <line x1="510" y1="120" x2="692" y2="120" stroke="#f59e0b" stroke-width="3"/>
            <text x="601" y="108" fill="#fbbf24" font-size="10" font-weight="bold" text-anchor="middle">⚠️ Stratum 프로토콜 채굴 패킷</text>
        </svg>
        """

    # 10. INC-010: 외주 협력사 유지보수 단말의 비인가 내부 서브넷 포트 스캔 및 SMB 취약점 탐색
    elif cid == "INC-010":
        return f"""
        <svg width="100%" height="240" viewBox="0 0 900 240" xmlns="http://www.w3.org/2000/svg">
            {svg_defs}
            <!-- Node 1: Vendor Laptop -->
            <circle cx="110" cy="120" r="58" fill="#0f172a" stroke="#38bdf8" stroke-width="2.5"/>
            <text x="110" y="104" fill="#ffffff" font-size="12" font-weight="bold" text-anchor="middle">외주 협력사 단말</text>
            <text x="110" y="122" fill="#93c5fd" font-size="10" text-anchor="middle">192.168.99.20</text>
            <text x="110" y="142" fill="#64748b" font-size="10" text-anchor="middle">[게스트망 접속단말]</text>

            <!-- Node 2: Core Firewall -->
            <rect x="350" y="80" width="160" height="80" rx="10" fill="url(#grad-node)" stroke="#f59e0b" stroke-width="2.5"/>
            <text x="430" y="107" fill="#ffffff" font-size="12" font-weight="bold" text-anchor="middle">코어 방화벽 / 게이트웨이</text>
            <text x="430" y="125" fill="#fbbf24" font-size="10" text-anchor="middle">10.0.0.1</text>
            <text x="430" y="143" fill="#ffd169" font-size="10" text-anchor="middle">[VLAN 경계 월경 감지]</text>

            <!-- Node 3: Core Subnet -->
            <circle cx="750" cy="120" r="58" fill="#450a0a" stroke="#ef4444" stroke-width="2.5"/>
            <text x="750" y="104" fill="#ffffff" font-size="12" font-weight="bold" text-anchor="middle">내부 코어 서브넷</text>
            <text x="750" y="122" fill="#fca5a5" font-size="10" text-anchor="middle">10.0.0.0/24 (254 IP)</text>
            <text x="750" y="142" fill="#ff7b88" font-size="10" font-weight="bold" text-anchor="middle">[SMB / RDP 무차별 스캔]</text>

            <!-- Connectors -->
            <line x1="168" y1="120" x2="350" y2="120" stroke="#f59e0b" stroke-width="3" stroke-dasharray="6,3"/>
            <text x="259" y="108" fill="#fbbf24" font-size="10" font-weight="bold" text-anchor="middle">게스트 VLAN 비인가 월경</text>

            <line x1="510" y1="120" x2="692" y2="120" stroke="#ef4444" stroke-width="3"/>
            <text x="601" y="108" fill="#ff8591" font-size="10" font-weight="bold" text-anchor="middle">⚠️ 10초 내 254개 IP 연속 SYN 스캔</text>
        </svg>
        """

    # 11. 일반 / 기타 인시던트 (Generic Fallback)
    else:
        return f"""
        <svg width="100%" height="240" viewBox="0 0 900 240" xmlns="http://www.w3.org/2000/svg">
            {svg_defs}
            <!-- Node 1: Actor -->
            <circle cx="110" cy="120" r="58" fill="#1e3a8a" stroke="#60a5fa" stroke-width="2.5"/>
            <text x="110" y="104" fill="#ffffff" font-size="12" font-weight="bold" text-anchor="middle">공격 발원지</text>
            <text x="110" y="122" fill="#93c5fd" font-size="10" text-anchor="middle">{inc.actor[:15]}</text>
            <text x="110" y="142" fill="#94a3b8" font-size="10" text-anchor="middle">[초기 진입]</text>

            <!-- Node 2: Gateway / Proxy -->
            <rect x="350" y="80" width="160" height="80" rx="10" fill="url(#grad-node)" stroke="#f59e0b" stroke-width="2.5"/>
            <text x="430" y="107" fill="#ffffff" font-size="12" font-weight="bold" text-anchor="middle">사내 게이트웨이</text>
            <text x="430" y="125" fill="#fbbf24" font-size="10" text-anchor="middle">Internal Gateway</text>
            <text x="430" y="143" fill="#ffd169" font-size="10" text-anchor="middle">[경유 및 세션 중계]</text>

            <!-- Node 3: Target Asset -->
            <circle cx="750" cy="120" r="58" fill="#4a044e" stroke="#c084fc" stroke-width="2.5"/>
            <text x="750" y="104" fill="#ffffff" font-size="12" font-weight="bold" text-anchor="middle">타깃 자산</text>
            <text x="750" y="122" fill="#e9d5ff" font-size="10" text-anchor="middle">{inc.target_asset[:15]}</text>
            <text x="750" y="142" fill="#c084fc" font-size="10" text-anchor="middle">[권한 침해]</text>

            <!-- Connectors -->
            <line x1="168" y1="120" x2="350" y2="120" stroke="#f59e0b" stroke-width="3" stroke-dasharray="6,3"/>
            <text x="259" y="108" fill="#fbbf24" font-size="11" font-weight="bold" text-anchor="middle">비정상 통신 유입</text>

            <line x1="510" y1="120" x2="692" y2="120" stroke="#ef4444" stroke-width="3.5"/>
            <text x="601" y="108" fill="#f87171" font-size="11" font-weight="bold" text-anchor="middle">권한 침해 및 변조</text>
        </svg>
        """

# 인터랙티브 맵 렌더링 (구글 맵 / 네이버 지도 스타일 패닝 & 줌)
def render_interactive_map(svg_markup: str):
    map_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
    <meta charset="utf-8">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        html, body {{
            width: 100%;
            height: 100%;
            overflow: hidden;
            background: #07111f;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        }}
        #map-container {{
            width: 100%;
            height: 100%;
            position: relative;
            overflow: hidden;
            border: 1px solid #1c2e47;
            border-radius: 12px;
            background: radial-gradient(circle at center, #0c1a2e 0%, #07111f 100%);
            cursor: grab;
            user-select: none;
        }}
        #map-container.grabbing {{
            cursor: grabbing;
        }}
        .controls {{
            position: absolute;
            top: 12px;
            right: 12px;
            z-index: 50;
            display: flex;
            flex-direction: column;
            gap: 6px;
        }}
        .ctrl-btn {{
            width: 32px;
            height: 32px;
            background: #111e33;
            color: #f1f5f9;
            border: 1px solid #2a4365;
            border-radius: 6px;
            font-size: 16px;
            font-weight: bold;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            box-shadow: 0 2px 6px rgba(0,0,0,0.4);
            transition: all 0.15s ease;
        }}
        .ctrl-btn:hover {{
            background: #1e3a5f;
            border-color: #38bdf8;
            color: #38bdf8;
            transform: scale(1.05);
        }}
        .ctrl-btn:active {{
            transform: scale(0.95);
        }}
        .info-badge {{
            position: absolute;
            bottom: 10px;
            left: 12px;
            z-index: 50;
            background: rgba(15, 23, 42, 0.85);
            border: 1px solid #1e293b;
            border-radius: 6px;
            padding: 4px 10px;
            font-size: 11px;
            color: #94a3b8;
            pointer-events: none;
            backdrop-filter: blur(4px);
        }}
        .zoom-badge {{
            position: absolute;
            bottom: 10px;
            right: 12px;
            z-index: 50;
            background: rgba(15, 23, 42, 0.85);
            border: 1px solid #1e293b;
            border-radius: 6px;
            padding: 4px 8px;
            font-size: 11px;
            font-weight: 600;
            color: #38bdf8;
            pointer-events: none;
            backdrop-filter: blur(4px);
        }}
        #map-canvas {{
            width: 100%;
            height: 100%;
            display: flex;
            align-items: center;
            justify-content: center;
            transform-origin: 0 0;
            will-change: transform;
        }}
        svg {{
            width: 100%;
            height: 100%;
            max-height: 280px;
            display: block;
        }}
    </style>
    </head>
    <body>
        <div id="map-container">
            <div class="controls">
                <button class="ctrl-btn" id="zoom-in" title="확대 (+)">+</button>
                <button class="ctrl-btn" id="zoom-out" title="축소 (−)">−</button>
                <button class="ctrl-btn" id="zoom-reset" title="초기화 (⟲)" style="color:#38bdf8;">⟲</button>
            </div>
            <div class="info-badge">
                🖱️ 마우스 드래그: 지도 이동 | 휠: 확대/축소 | ⟲: 초기화
            </div>
            <div class="zoom-badge" id="zoom-text">
                100%
            </div>
            <div id="map-canvas">
                {svg_markup}
            </div>
        </div>

        <script>
            const container = document.getElementById('map-container');
            const canvas = document.getElementById('map-canvas');
            const zoomText = document.getElementById('zoom-text');
            const btnIn = document.getElementById('zoom-in');
            const btnOut = document.getElementById('zoom-out');
            const btnReset = document.getElementById('zoom-reset');

            let scale = 1.0;
            let panX = 0;
            let panY = 0;
            let isDragging = false;
            let startX = 0;
            let startY = 0;

            function update() {{
                canvas.style.transform = `translate(${{panX}}px, ${{panY}}px) scale(${{scale}})`;
                zoomText.textContent = Math.round(scale * 100) + '%';
            }}

            container.addEventListener('mousedown', (e) => {{
                if (e.target.closest('.controls')) return;
                isDragging = true;
                container.classList.add('grabbing');
                startX = e.clientX - panX;
                startY = e.clientY - panY;
            }});

            window.addEventListener('mousemove', (e) => {{
                if (!isDragging) return;
                panX = e.clientX - startX;
                panY = e.clientY - startY;
                update();
            }});

            window.addEventListener('mouseup', () => {{
                if (isDragging) {{
                    isDragging = false;
                    container.classList.remove('grabbing');
                }}
            }});

            container.addEventListener('wheel', (e) => {{
                e.preventDefault();
                const rect = container.getBoundingClientRect();
                const mouseX = e.clientX - rect.left;
                const mouseY = e.clientY - rect.top;
                
                const factor = e.deltaY < 0 ? 1.15 : 0.87;
                const newScale = Math.min(Math.max(0.4, scale * factor), 4.0);
                
                panX = mouseX - (mouseX - panX) * (newScale / scale);
                panY = mouseY - (mouseY - panY) * (newScale / scale);
                scale = newScale;
                update();
            }}, {{ passive: false }});

            btnIn.addEventListener('click', () => {{
                const rect = container.getBoundingClientRect();
                const cx = rect.width / 2;
                const cy = rect.height / 2;
                const newScale = Math.min(4.0, scale * 1.25);
                panX = cx - (cx - panX) * (newScale / scale);
                panY = cy - (cy - panY) * (newScale / scale);
                scale = newScale;
                update();
            }});

            btnOut.addEventListener('click', () => {{
                const rect = container.getBoundingClientRect();
                const cx = rect.width / 2;
                const cy = rect.height / 2;
                const newScale = Math.max(0.4, scale * 0.8);
                panX = cx - (cx - panX) * (newScale / scale);
                panY = cy - (cy - panY) * (newScale / scale);
                scale = newScale;
                update();
            }});

            btnReset.addEventListener('click', () => {{
                scale = 1.0;
                panX = 0;
                panY = 0;
                update();
            }});

            container.addEventListener('dblclick', (e) => {{
                if (e.target.closest('.controls')) return;
                const rect = container.getBoundingClientRect();
                const mouseX = e.clientX - rect.left;
                const mouseY = e.clientY - rect.top;
                const newScale = Math.min(4.0, scale * 1.35);
                panX = mouseX - (mouseX - panX) * (newScale / scale);
                panY = mouseY - (mouseY - panY) * (newScale / scale);
                scale = newScale;
                update();
            }});
        </script>
    </body>
    </html>
    """
    components.html(map_html, height=310)


if menu == "대시보드 종합 관제":
    st.markdown("""
    <div style="margin-bottom: 20px;">
        <h1 style="margin:0; font-size: 39px; font-weight: 800; color:#ffffff; letter-spacing: -0.5px;">Shadow AI Dashboard</h1>
        <span style="color: #9fb0c8; font-size: 14px;">실시간 이기종 로그 연계 침해사고 재구성 및 내부 데이터 거버넌스 모니터링 (Zero Trust XDR)</span>
    </div>
    """, unsafe_allow_html=True)

    # 위험도별 인시던트 목록 분할
    all_incident_ids = [inc.incident_id for inc in incidents]
    crit_high_ids = [inc.incident_id for inc in incidents if inc.severity in [Severity.CRITICAL, Severity.HIGH]]
    med_ids = [inc.incident_id for inc in incidents if inc.severity == Severity.MEDIUM]
    low_ids = [inc.incident_id for inc in incidents if inc.severity == Severity.LOW]

    # 기본 선택 인시던트 유효성 검증
    if "selected_incident_id" not in st.session_state or st.session_state.selected_incident_id not in all_incident_ids:
        st.session_state.selected_incident_id = all_incident_ids[0]

    # 3대 위험도별 드롭다운 콜백 함수 (다른 그룹의 드롭다운 값은 리셋하여 재선택 가능하도록 처리)
    def on_select_crit_high():
        val = st.session_state.sel_crit_high_dropdown
        if val:
            st.session_state.selected_incident_id = val
            st.session_state.sel_med_dropdown = None
            st.session_state.sel_low_dropdown = None

    def on_select_med():
        val = st.session_state.sel_med_dropdown
        if val:
            st.session_state.selected_incident_id = val
            st.session_state.sel_crit_high_dropdown = None
            st.session_state.sel_low_dropdown = None

    def on_select_low():
        val = st.session_state.sel_low_dropdown
        if val:
            st.session_state.selected_incident_id = val
            st.session_state.sel_crit_high_dropdown = None
            st.session_state.sel_med_dropdown = None

    # 드롭다운 옵션 레이블 포맷터
    # 🔴 사용자 요청: 긴급 인시던트 드롭다운 메뉴 안의 모든 항목 앞 위험도 색상을 '빨강(🔴)'으로 통일
    def format_crit_high_dropdown(inc_id: str) -> str:
        inc = ctx.correlation_engine.get_incident(inc_id)
        if not inc:
            return inc_id
        return f"🔴 {inc.incident_id} | {inc.title}"

    def format_med_dropdown(inc_id: str) -> str:
        inc = ctx.correlation_engine.get_incident(inc_id)
        if not inc:
            return inc_id
        return f"🟡 {inc.incident_id} | {inc.title}"

    def format_low_dropdown(inc_id: str) -> str:
        inc = ctx.correlation_engine.get_incident(inc_id)
        if not inc:
            return inc_id
        return f"🟢 {inc.incident_id} | {inc.title}"

    # 세션 상태 안전 동기화 (현재 선택된 인시던트가 속한 그룹만 활성화하고, 나머지는 None으로 설정하여 변경 감지 보장)
    cur_sel = st.session_state.selected_incident_id

    if cur_sel in crit_high_ids:
        st.session_state.sel_crit_high_dropdown = cur_sel
        st.session_state.sel_med_dropdown = None
        st.session_state.sel_low_dropdown = None
    elif cur_sel in med_ids:
        st.session_state.sel_med_dropdown = cur_sel
        st.session_state.sel_crit_high_dropdown = None
        st.session_state.sel_low_dropdown = None
    elif cur_sel in low_ids:
        st.session_state.sel_low_dropdown = cur_sel
        st.session_state.sel_crit_high_dropdown = None
        st.session_state.sel_med_dropdown = None

    # 각 드롭다운의 초기 인덱스 계산
    crit_high_idx = crit_high_ids.index(cur_sel) if cur_sel in crit_high_ids else None
    med_idx = med_ids.index(cur_sel) if cur_sel in med_ids else None
    low_idx = low_ids.index(cur_sel) if cur_sel in low_ids else None

    # 🌟 [2단계 위험 상태 기계] 실시간 감시 대상 (WATCH) 현황판
    watch_users = ctx.correlation_engine.get_watch_users()
    active_watch = [u for u in watch_users if u.get("state") == "WATCH"]
    if active_watch:
        watch_rows = []
        for w in active_watch:
            reasons_str = " / ".join(w.get("reasons", []))
            watch_rows.append(f"<div style='margin-bottom:4px;'>• <b style='color:#ffffff;'>{w['user']}</b> <span style='color:#fbbf24; font-weight:700;'>[위험도 {w['score']}점]</span> <span style='color:#cbd5e1;'>— 사유: {reasons_str}</span></div>")
        st.markdown(f"""
        <div style="background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%); border: 1.5px solid #f59e0b; border-left: 6px solid #fbbf24; border-radius: 12px; padding: 16px 22px; margin-bottom: 20px; box-shadow: 0 4px 14px rgba(245, 158, 11, 0.25);">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 8px;">
                <span style="font-weight:800; color:#fbbf24; font-size:15px; display:flex; align-items:center; gap:6px;">
                    👁️ 실시간 사전 감시 대상 (WATCH) — {len(active_watch)}명 승격 포착 (데이터 전송 전 선제 탐지)
                </span>
                <span style="font-size:12px; color:#94a3b8; background:rgba(15,23,42,0.6); padding:3px 8px; border-radius:6px; border:1px solid #334155;">30분 내 외부 전송 없을 시 자동 복귀 (Self-healing TTL)</span>
            </div>
            <div style="font-size:13px;">
                {''.join(watch_rows)}
            </div>
        </div>
        """, unsafe_allow_html=True)

    # 📜 실시간 2단계 상태 머신 감사 이력 (SQLite risk_history)
    with st.expander("📜 실시간 2단계 상태 머신 감사 이력 (SQLite `risk_history`)", expanded=False):
        hist = ctx.correlation_engine.store.get_risk_history(10)
        if hist:
            df_hist = pd.DataFrame(hist)[["at", "user", "from_state", "to_state", "reason"]]
            df_hist.columns = ["일시 (UTC)", "대상자", "이전 상태", "전이 상태", "판정 사유"]
            st.dataframe(df_hist, use_container_width=True)
        else:
            st.caption("아직 기록된 상태 전이 이력이 없습니다. 좌측 사이드바 시뮬레이터를 실행해보세요.")

    # 3대 위험도별 KPI 카드 및 드롭다운 메뉴 (CRITICAL/HIGH, MEDIUM, LOW로 3분할 균등 확장)
    kpi1, kpi2, kpi3 = st.columns(3)

    # [파트 1] CRITICAL / HIGH
    with kpi1:
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-title critical-text">
                {tooltip("🚨", "CRITICAL / HIGH 긴급 경보", "즉각적인 격리 또는 차단이 요구되는 활성 공격 및 기밀 유출 사건입니다.")} CRITICAL / HIGH
            </div>
            <div class="kpi-value critical-text">{len(crit_high_ids)}</div>
            <div class="kpi-sub">긴급 대응 필요 침해 킬체인</div>
        </div>
        """, unsafe_allow_html=True)
        st.selectbox(
            "🔴 긴급 인시던트 선택 (7건)",
            options=crit_high_ids,
            index=crit_high_idx,
            placeholder="🔴 긴급 인시던트 선택 (7건)...",
            format_func=format_crit_high_dropdown,
            key="sel_crit_high_dropdown",
            on_change=on_select_crit_high,
            help="치명(Critical) 및 고위험(High) 긴급 대응 인시던트 목록입니다."
        )

    # [파트 2] MEDIUM (주의)
    with kpi2:
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-title medium-text">
                {tooltip("⚠️", "MEDIUM 주의 단계", "비인가 포트 스캔, 마이닝 풀 질의 등 정찰 행위 및 정책 위반 사항입니다.")} MEDIUM (주의)
            </div>
            <div class="kpi-value medium-text">{len(med_ids)}</div>
            <div class="kpi-sub">내부 비인가 탐색 및 반출 의심</div>
        </div>
        """, unsafe_allow_html=True)
        st.selectbox(
            "🟡 주의 인시던트 선택 (2건)",
            options=med_ids,
            index=med_idx,
            placeholder="🟡 주의 인시던트 선택 (2건)...",
            format_func=format_med_dropdown,
            key="sel_med_dropdown",
            on_change=on_select_med,
            help="주의(Medium) 단계 인시던트 목록입니다."
        )

    # [파트 3] LOW (경미)
    with kpi3:
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-title low-text">
                {tooltip("🟢", "LOW 경미 단계", "단순 정책 위반 또는 저위험 포트 스캔 탐지 사항입니다.")} LOW (경미)
            </div>
            <div class="kpi-value low-text">{len(low_ids)}</div>
            <div class="kpi-sub">저위험 단순 정책 위반 탐지</div>
        </div>
        """, unsafe_allow_html=True)
        st.selectbox(
            "🟢 경미 인시던트 선택 (1건)",
            options=low_ids,
            index=low_idx,
            placeholder="🟢 경미 인시던트 선택 (1건)...",
            format_func=format_low_dropdown,
            key="sel_low_dropdown",
            on_change=on_select_low,
            help="경미(Low) 단계 인시던트 목록입니다."
        )

    # 선택된 분석 대상 인시던트 종합 정보 카드 (전폭 100% 확장 및 세로 길이 대폭 확대)
    selected_inc = ctx.correlation_engine.get_incident(st.session_state.selected_incident_id)
    sev_badge_bar = {
        Severity.CRITICAL: '<span class="badge badge-critical" style="font-size:13px; padding:5px 12px;">CRITICAL (치명)</span>',
        Severity.HIGH: '<span class="badge badge-high" style="font-size:13px; padding:5px 12px;">HIGH (고위험)</span>',
        Severity.MEDIUM: '<span class="badge badge-medium" style="font-size:13px; padding:5px 12px;">MEDIUM (주의)</span>',
        Severity.LOW: '<span class="badge badge-low" style="font-size:13px; padding:5px 12px;">LOW (경미)</span>'
    }.get(selected_inc.severity, "")

    st.markdown(f"""
    <div style="background: linear-gradient(135deg, #0a1728 0%, #0f233d 50%, #162f52 100%); border: 1.5px solid #1e40af; border-left: 6px solid #38bdf8; border-radius: 12px; padding: 22px 28px; margin-top: 14px; margin-bottom: 8px; box-shadow: 0 6px 20px rgba(0,0,0,0.45);">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
            <div style="font-size: 13px; font-weight: 700; color: #38bdf8; letter-spacing: 0.8px; text-transform: uppercase; display: flex; align-items: center; gap: 8px;">
                <span style="display:inline-block; width:9px; height:9px; border-radius:50%; background:#38bdf8; box-shadow:0 0 10px #38bdf8;"></span>
                선택된 분석 대상 인시던트 종합 정보
            </div>
            <div style="font-size: 13px; color: #94a3b8;">
                위협 분류: <b style="color: #c084fc; font-size:14px; margin-left:4px;">{selected_inc.category.value}</b>
            </div>
        </div>
        <div style="display: flex; align-items: center; gap: 14px; margin-bottom: 14px; flex-wrap: wrap;">
            <span style="font-size: 24px; font-weight: 900; color: #ffffff; letter-spacing: -0.5px;">{selected_inc.incident_id}</span>
            {sev_badge_bar}
            <span style="font-size: 17px; font-weight: 700; color: #f8fafc; line-height: 1.4;">{selected_inc.title}</span>
        </div>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 14px; background: rgba(7, 17, 31, 0.7); padding: 14px 20px; border-radius: 10px; border: 1px solid rgba(56, 189, 248, 0.2);">
            <div style="font-size: 13px; color: #94a3b8; display:flex; align-items:center;">
                <span style="font-size:15px; margin-right:6px;">📍</span> <b>공격 발원지:</b> <span style="color:#f87171; font-weight:700; font-size:14px; margin-left:6px;">{selected_inc.actor}</span>
            </div>
            <div style="font-size: 13px; color: #94a3b8; display:flex; align-items:center;">
                <span style="font-size:15px; margin-right:6px;">🎯</span> <b>타깃 자산:</b> <span style="color:#38bdf8; font-weight:700; font-size:14px; margin-left:6px;">{selected_inc.target_asset}</span>
            </div>
            <div style="font-size: 13px; color: #94a3b8; display:flex; align-items:center;">
                <span style="font-size:15px; margin-right:6px;">⚡</span> <b>상관분석 점수:</b> <span style="color:#ff8591; font-weight:800; font-size:16px; margin-left:6px;">{selected_inc.score}점</b>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("<hr style='border:none; border-top:1px solid #1c2e47; margin:20px 0 16px 0;'>", unsafe_allow_html=True)
    
    map_title = f"""
    <div class="box-title" style="display:flex; justify-content:space-between; align-items:center;">
        <span>{tooltip("🌐", "네트워크 토폴로지 맵", "선택된 인시던트의 발원지, 경유지, 타깃 자산 간의 통신 포트와 공격 이동 경로를 실시간 시각화합니다. 마우스 휠로 확대/축소하고 드래그하여 지도를 자유롭게 이동할 수 있습니다.")} 네트워크 토폴로지 맵 (Network Map)</span>
        <span style="font-size:12px; font-weight:normal; color:#64748b;">🔍 마우스 휠 확대/축소 & 드래그 이동 지원</span>
    </div>
    """
    st.markdown(map_title, unsafe_allow_html=True)
    st.markdown(f"<div style='font-size:13px; color:#9fb0c8; margin-bottom:10px;'>현재 분석 대상: <b style='color:#38bdf8;'>{selected_inc.incident_id}</b> ({selected_inc.category.value}) — <b>{selected_inc.title}</b></div>", unsafe_allow_html=True)

    raw_svg = generate_dynamic_network_svg(selected_inc)
    render_interactive_map(raw_svg)

    # 하단: 인시던트 상세 타임라인 & 판단 근거
    st.markdown("<hr style='border:none; border-top:1px solid #1c2e47; margin:24px 0 16px 0;'>", unsafe_allow_html=True)
    det_col1, det_col2 = st.columns([7, 3])

    with det_col1:
        sev_badge = {
            Severity.CRITICAL: '<span class="badge badge-critical">CRITICAL (치명)</span>',
            Severity.HIGH: '<span class="badge badge-high">HIGH (고위험)</span>',
            Severity.MEDIUM: '<span class="badge badge-medium">MEDIUM (주의)</span>',
            Severity.LOW: '<span class="badge badge-low">LOW (경미)</span>'
        }.get(selected_inc.severity, "")
        
        detail_header = f"""
        <div class="box-title">
            {tooltip("🔍", "인시던트 상세 및 공격 킬체인", "해당 인시던트에 결합된 상세 이벤트 목록과 재구성된 킬체인 단계입니다.")} 인시던트 상세 — {selected_inc.incident_id} {sev_badge}
        </div>
        """
        st.markdown(detail_header, unsafe_allow_html=True)
        st.markdown(f"<p style='color:#c9d3e2; font-size:14px; margin-bottom:12px;'><b>공격 명칭:</b> {selected_inc.title}<br><b>상세 요약:</b> {selected_inc.summary}</p>", unsafe_allow_html=True)
        
        st.markdown(f"<span style='font-size:13px; font-weight:700; color:#9fb0c8;'>{tooltip('⏱️', '공격 시퀀스 순서', '공격자가 내부망에 침투하여 목적을 달성하기까지의 행위 순서입니다.')} 공격 행위 타임라인 (Attack Sequence):</span><br>", unsafe_allow_html=True)
        
        # 홉(Hop) 기반 타임라인 자동 생성
        steps_html_parts = []
        for idx, h in enumerate(selected_inc.network_hops):
            steps_html_parts.append(f'<span class="timeline-step">{idx+1}. {h.from_node} ➔ {h.to_node} (:{h.port})</span>')
        steps_html = f'<div style="margin-top:8px;">{" ".join(steps_html_parts)}</div>'
        st.markdown(steps_html, unsafe_allow_html=True)

        st.markdown(f"<br><span style='font-size:13px; font-weight:700; color:#9fb0c8;'>{tooltip('🛡️', '상관분석 판단 근거', '서로 다른 이기종 로그를 단일 공격으로 결합한 수학적/규칙적 판단 근거입니다.')} 상관분석 판단 근거 (Explainable Evidence):</span>", unsafe_allow_html=True)
        for ev in selected_inc.evidences:
            st.markdown(f"<div class='evidence-item'>✓ {ev}</div>", unsafe_allow_html=True)

    with det_col2:
        soar_header = f"""
        <div class="box-title">
            {tooltip("⚡", "SOAR 원클릭 자동 대응", "보안관제 요원이 클릭 한 번으로 방화벽 차단 룰 배포 및 세션 격리를 수행할 수 있는 자동화 조치입니다.")} SOAR 자동 대응
        </div>
        """
        st.markdown(soar_header, unsafe_allow_html=True)
        st.markdown(f"""
        <div style="background:#132238; padding:14px; border-radius:10px; margin-bottom:12px;">
            <div style="font-size:12px; color:#9fb0c8;">상관분석 신뢰 점수</div>
            <div style="font-size:28px; font-weight:bold; color:#ff5b6b;">{selected_inc.score} / 100</div>
            <div style="font-size:12px; color:#62d487;">최종 위험도: {selected_inc.severity.value}</div>
        </div>
        """, unsafe_allow_html=True)
        
        if st.button("🚨 방화벽 차단 룰 즉시 배포", key="btn_fw", use_container_width=True, help="해당 공격 발원지 IP 및 C2 목적지를 경계 방화벽 차단 목록에 영구 추가합니다."):
            st.success("✅ iptables / 방화벽 차단 정책이 즉시 배포되었습니다.")
        if st.button("🔒 활성 계정 세션 즉시 만료", key="btn_revoke", use_container_width=True, help="침해된 계정의 모든 SSO 세션 및 토큰을 무효화합니다."):
            st.success("✅ 해당 계정의 모든 SSO 세션이 강제 종료되었습니다.")
        if st.button("📢 Slack 보안팀 긴급 채널 전파", key="btn_slack", use_container_width=True, help="Slack #incident-critical 채널로 경보 웹훅을 전파합니다."):
            st.info("📨 Slack #incident-alert 채널로 웹훅 전파 완료!")


# ==========================================
# VIEW 2: 침해사고 킬체인 분석 (Lateral Movement)
# ==========================================
elif menu == "침해사고 킬체인 분석":
    top_col1, top_col2 = st.columns([7, 3])
    with top_col1:
        st.markdown("<h2>🎯 외부 침투 및 침해사고 킬체인(Lateral Movement) 심층 분석</h2>", unsafe_allow_html=True)
    with top_col2:
        st.markdown("<div style='margin-top: 10px;'></div>", unsafe_allow_html=True)
        st.button(
            "⬅️ 대시보드 종합 관제로 돌아가기",
            on_click=navigate_to,
            args=("대시보드 종합 관제",),
            use_container_width=True
        )

    incident_ids = [inc.incident_id for inc in incidents]
    curr_target_id = st.session_state.get("selected_incident_id", incidents[0].incident_id)
    if curr_target_id not in incident_ids:
        curr_target_id = incident_ids[0]
    curr_target_idx = incident_ids.index(curr_target_id)

    def format_inc_option(inc_id: str) -> str:
        inc = ctx.correlation_engine.get_incident(inc_id)
        if not inc:
            return inc_id
        sev_badge = {
            Severity.CRITICAL: "🔴 [CRITICAL]",
            Severity.HIGH: "🟠 [HIGH]",
            Severity.MEDIUM: "🟡 [MEDIUM]",
            Severity.LOW: "🟢 [LOW]"
        }.get(inc.severity, "⚪")
        return f"{sev_badge} {inc.incident_id} | {inc.title}"

    def on_killchain_dropdown():
        st.session_state.selected_incident_id = st.session_state.killchain_tab_selectbox

    st.session_state.killchain_tab_selectbox = st.session_state.selected_incident_id

    sel_tab_id = st.selectbox(
        "🔎 분석 대상 인시던트 선택 (드롭다운으로 변경 가능)",
        options=incident_ids,
        format_func=format_inc_option,
        key="killchain_tab_selectbox",
        on_change=on_killchain_dropdown
    )

    target_inc = ctx.correlation_engine.get_incident(st.session_state.selected_incident_id)

    st.info(f"**[{target_inc.incident_id}] {target_inc.title}**\n\n{target_inc.summary}")

    # 침해사고 네트워크 토폴로지 맵
    st.markdown(f'<div class="box-title">🌐 침해사고 네트워크 토폴로지 맵 ({target_inc.incident_id})</div>', unsafe_allow_html=True)
    raw_svg = generate_dynamic_network_svg(target_inc)
    render_interactive_map(raw_svg)

    col1, col2 = st.columns([5, 5])
    with col1:
        st.markdown(f'<div class="box-title">📍 재구성된 네트워크 홉(Hop) 명세 ({target_inc.incident_id})</div>', unsafe_allow_html=True)
        if target_inc.network_hops:
            hops_data = []
            for h in target_inc.network_hops:
                hops_data.append({
                    "출발지(From)": h.from_node,
                    "목적지(To)": h.to_node,
                    "포트": h.port,
                    "유형": h.hop_type.upper()
                })
            st.table(pd.DataFrame(hops_data))
        else:
            st.markdown(f"""
            <div style="background:#0d1a2b; border:1px solid #1c2e47; border-radius:8px; padding:14px; color:#94a3b8; font-size:13px;">
                단일 호스트 내부 공격 및 데이터 유출 시퀀스 감지<br>
                • 공격 발원: <b style="color:#f87171;">{target_inc.actor}</b><br>
                • 타깃 자산: <b style="color:#38bdf8;">{target_inc.target_asset}</b>
            </div>
            """, unsafe_allow_html=True)

    with col2:
        st.markdown('<div class="box-title">🛡️ Zero Trust 대응 조치 및 격리 상태</div>', unsafe_allow_html=True)
        st.markdown(f"""
        1. **발원지/단말 제어:** `{target_inc.actor}` 관련 활성 세션 강제 만료 및 EDR 격리 대기
        2. **타깃 자산 보호:** `{target_inc.target_asset}` 대상 접근 정책 긴급 강화 및 Direct 접근 차단
        3. **포렌식 아티팩트 보존:** 해당 호스트 메모리 덤프 및 Syslog 스냅샷 생성 완료
        """)


# VIEW 3: 섀도우 AI·IT 거버넌스 (Shadow IT/AI)
# ==========================================
elif menu == "섀도우 AI·IT 거버넌스":
    st.markdown("<h2>🤖 사내 섀도우 IT 및 생성형 AI 거버넌스 대시보드</h2>", unsafe_allow_html=True)
    st.caption("DNS 질의를 실시간 감시하여 사내 미승인 SaaS/AI 서비스를 식별하고 '무조건 차단'이 아닌 '정식 승인 및 양성화'로 유도합니다.")

    with st.expander("📡 원본 DNS 로그 스트림 실시간 유입 확인 (dnsmasq raw log)", expanded=False):
        st.code("""
09:12:04  192.168.10.45  slack.com       -> 정식 계약 협업 도구
09:12:47  192.168.10.45  chatgpt.com     -> 생성형 AI (고위험 감지)
09:15:22  192.168.10.88  dropbox.com     -> 개인 클라우드 저장소
09:16:01  192.168.10.45  api.openai.com  -> AI API 대량 데이터 전송
09:31:19  192.168.10.12  notion.so       -> 문서 도구 (관찰 대상)
10:02:55  192.168.10.88  wetransfer.com  -> 일회성 대용량 전송 (차단 권고)
        """, language="bash")

    for asset in shadow_assets:
        badge_style = "badge-high" if asset.risk_level == Severity.HIGH else ("badge-medium" if asset.risk_level == Severity.MEDIUM else "badge-low")
        status_text = "정식 승인됨" if asset.sanction_status == SanctionStatus.APPROVED else ("명시적 차단" if asset.sanction_status == SanctionStatus.BLOCKED else "미승인 검토중")
        
        st.markdown(f"""
        <div style="background:#0d1a2b; border:1px solid #1c2e47; border-radius:12px; padding:18px; margin-bottom:12px;">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <div>
                    <span style="font-size:18px; font-weight:bold; color:#ffffff;">{asset.domain}</span>
                    <span style="color:#9fb0c8; font-size:13px; margin-left:8px;">({asset.service_name} · {asset.category})</span>
                </div>
                <div>
                    <span class="badge {badge_style}">{asset.risk_level.value}</span>
                    <span class="badge" style="background:#1b2a3f; color:#9fb0c8; margin-left:4px;">{status_text}</span>
                </div>
            </div>
            <div style="font-size:13px; color:#c9d3e2; margin-top:8px;">
                👥 사용 현황: <b>{asset.department_count}개 부서</b> / <b>{asset.user_count}명 임직원 사용</b> | 사용 빈도: {asset.usage_frequency}
            </div>
            <div style="font-size:13px; color:#9ee0b2; margin-top:4px;">
                💡 <b>Gemini AI 진단:</b> {asset.ai_diagnosis}
            </div>
            <div style="font-size:13px; color:#ffd169; margin-top:2px;">
                🔄 <b>사내 대체 도구:</b> {asset.recommended_alternative or '사내 표준 도구 유지'}
            </div>
        </div>
        """, unsafe_allow_html=True)

        act_col1, act_col2, act_col3 = st.columns([1, 1, 1])
        with act_col1:
            if st.button(f"✅ 정식 승인(양성화)", key=f"app_{asset.domain}", use_container_width=True, help="해당 SaaS를 회사 승인 소프트웨어 목록에 등록하고 정식 라이선스 계약을 추진합니다."):
                ctx.governance_engine.update_sanction_status(asset.domain, SanctionStatus.APPROVED)
                st.success(f"'{asset.domain}' 서비스가 사내 승인 목록으로 전환되었습니다.")
                st.rerun()
        with act_col2:
            if st.button(f"💬 사내 프라이빗 도구 안내(Slack)", key=f"guide_{asset.domain}", use_container_width=True, help="사용자에게 사내 승인 대체 보안 도구 사용 가이드를 DM으로 발송합니다."):
                st.info(f"해당 사용자 그룹에게 '{asset.recommended_alternative}' 사용 가이드가 발송되었습니다.")
        with act_col3:
            if st.button(f"⛔ 도메인 차단 룰 생성", key=f"blk_{asset.domain}", use_container_width=True, help="DNS 싱크홀 및 방화벽 차단 정책에 등록하여 접근을 차단합니다."):
                ctx.governance_engine.update_sanction_status(asset.domain, SanctionStatus.BLOCKED)
                st.warning(f"'{asset.domain}' DNS 싱크홀 및 방화벽 차단 룰이 등록되었습니다.")
                st.rerun()


# ==========================================
# VIEW 4: Zero Trust 승인센터 & 접근통제 (IDAM)
# ==========================================
elif menu == "Zero Trust 승인센터":
    st.markdown("<h2>⚖️ Zero Trust 동적 승인센터 & 접근통제 (IDAM Gate)</h2>", unsafe_allow_html=True)
    st.caption("3과목(접근통제) 연계 모듈: 직무 기반(RBAC) 조건부 접근 제어 및 임직원 승인 요청 심의선")

    st.markdown('<div class="box-title">📋 대기 중인 임직원 SaaS/AI 승인 요청 목록</div>', unsafe_allow_html=True)
    
    req_df = pd.DataFrame([
        {"요청 번호": "REQ-2026-081", "신청자": "김대리 (마케팅팀)", "대상 서비스": "ChatGPT Plus", "사유": "하반기 캠페인 카피라이팅 작성 지원", "기밀문서 포함 여부": "미포함 서약 완료", "상태": "심의 대기"},
        {"요청 번호": "REQ-2026-082", "신청자": "이과장 (재무팀)", "대상 서비스": "Dropbox Business", "사유": "외부 회계법인 대용량 감사 자료 송수신", "기밀문서 포함 여부": "재무제표 포함", "상태": "보안성 검토 필요"},
        {"요청 번호": "REQ-2026-083", "신청자": "박엔지니어 (개발1팀)", "대상 서비스": "Claude.ai Code", "사유": "레거시 파이썬 코드 리팩토링 검토", "기밀문서 포함 여부": "사내 소스코드", "상태": "심의 대기"}
    ])
    st.dataframe(req_df, hide_index=True, use_container_width=True)


# ==========================================
# VIEW 5: 원천 이벤트 탐색 (Raw Event Explorer)
# ==========================================
elif menu == "원천 이벤트 탐색":
    st.markdown("<h2>🔎 원천 보안 이벤트 스트림 탐색 (Event Explorer)</h2>", unsafe_allow_html=True)
    
    events = ctx.initial_events
    ev_list = []
    for e in events:
        ev_list.append({
            "이벤트 ID": e.event_id,
            "발생 시각": e.timestamp.strftime('%H:%M:%S'),
            "로그 소스": e.log_source.value.upper(),
            "출발지": f"{e.actor.src_ip}" + (f":{e.actor.src_port}" if e.actor.src_port else ""),
            "사용자": e.actor.user_id or "-",
            "목적지": e.target.domain or f"{e.target.dst_ip}:{e.target.dst_port}",
            "행위": e.action.value,
            "원천 로그": e.raw_message[:60] + "..." if e.raw_message else "-"
        })
    st.dataframe(pd.DataFrame(ev_list), hide_index=True, use_container_width=True)
