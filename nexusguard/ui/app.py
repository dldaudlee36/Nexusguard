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
    page_title="Dashboard | NexusGuard",
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

    /* 사이드바 시뮬레이터 버튼 균일 크기 고정 및 줄바꿈 방지 */
    section[data-testid="stSidebar"] div.stButton > button {
        height: 56px !important;
        min-height: 56px !important;
        max-height: 56px !important;
        width: 100% !important;
        display: flex !important;
        flex-direction: column !important;
        align-items: center !important;
        justify-content: center !important;
        font-size: 12.5px !important;
        font-weight: 700 !important;
        line-height: 1.25 !important;
        padding: 4px 6px !important;
        border-radius: 8px !important;
        white-space: pre-line !important;
    }

    /* KPI 카드 스타일 */
    .kpi-card {
        background: #0d1a2b;
        border: 1px solid #1c2e47;
        border-radius: 14px;
        padding: 16px 20px;
        margin-bottom: 15px;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
        min-height: 125px;
        height: 125px;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
        box-sizing: border-box;
    }
    .kpi-title {
        font-size: 13px;
        font-weight: 600;
        color: #9fb0c8;
        margin-bottom: 6px;
    }
    .kpi-value {
        font-size: 32px;
        font-weight: 700;
        color: #ffffff;
        letter-spacing: -0.5px;
        line-height: 1.2;
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
    /* Dashboard 제목 호버 툴팁 */
    .dashboard-title-box {
        position: relative;
        display: inline-block;
        margin-bottom: 20px;
        cursor: pointer;
    }
    .dashboard-title {
        margin: 0;
        font-size: 38px;
        font-weight: 800;
        color: #ffffff;
        letter-spacing: -0.5px;
        display: flex;
        align-items: center;
        gap: 10px;
    }
    .dashboard-info-icon {
        font-size: 20px;
        color: #64748b;
        cursor: pointer;
        transition: color 0.2s;
    }
    .dashboard-title-box:hover .dashboard-info-icon {
        color: #38bdf8;
    }
    .dashboard-title-tooltip {
        visibility: hidden;
        opacity: 0;
        position: absolute;
        top: calc(100% + 6px);
        left: 0;
        background-color: #0c1c33;
        color: #93c5fd;
        font-size: 13px;
        font-weight: 500;
        padding: 8px 16px;
        border-radius: 8px;
        border: 1px solid #2563eb;
        box-shadow: 0 10px 28px rgba(0, 0, 0, 0.8);
        white-space: nowrap;
        z-index: 9999;
        transition: opacity 0.2s ease, visibility 0.2s ease;
        pointer-events: none;
    }
    .dashboard-title-box:hover .dashboard-title-tooltip {
        visibility: visible;
        opacity: 1;
    }

    /* 통합 인시던트 선택기 단일 박스 컨테이너 */
    div[data-testid="stVerticalBlockBorderWrapper"] {
        background-color: #0c182a !important;
        border: 1.5px solid #1c324e !important;
        border-radius: 12px !important;
        padding: 14px 20px 16px 20px !important;
        box-shadow: 0 4px 16px rgba(0, 0, 0, 0.35) !important;
        margin-bottom: 16px !important;
    }
    /* 통합 선택 박스 내부 불필요한 라벨 및 도움말 아이콘 완전 은닉 */
    div[data-testid="stSelectbox"] label,
    div[data-testid="stSelectbox"] [data-testid="stWidgetLabel"] {
        display: none !important;
        height: 0 !important;
        margin: 0 !important;
        padding: 0 !important;
    }

    /* 🌟 인시던트 선택 박스 세로 높이 확대 및 시인성 향상 */
    div[data-testid="stSelectbox"] div[data-baseweb="select"] > div {
        min-height: 64px !important;
        height: 64px !important;
        background-color: #0b1a2e !important;
        border: 2px solid #3b82f6 !important;
        border-radius: 12px !important;
        box-shadow: 0 4px 16px rgba(37, 99, 235, 0.25) !important;
        padding: 6px 18px !important;
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
        font-size: 16px !important;
        font-weight: 700 !important;
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

    /* 🌟 SOAR 긴급 대응 액션 버튼 시인성 극대화 (세로 높이 대폭 확장: 64px) */
    div[class*="st-key-btn_fw"] button,
    div[class*="st-key-btn_revoke"] button,
    div[class*="st-key-btn_slack"] button,
    div[class*="st-key-btn_jump_kc"] button {
        min-height: 64px !important;
        height: 64px !important;
        padding: 16px 14px !important;
        font-size: 14.5px !important;
        font-weight: 700 !important;
        border-radius: 10px !important;
        line-height: 1.4 !important;
        border: 1.5px solid #223c62 !important;
        background: linear-gradient(180deg, #13233c 0%, #0c182b 100%) !important;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.35) !important;
        transition: all 0.2s ease-in-out !important;
    }
    div[class*="st-key-btn_fw"] button:hover,
    div[class*="st-key-btn_revoke"] button:hover,
    div[class*="st-key-btn_slack"] button:hover,
    div[class*="st-key-btn_jump_kc"] button:hover {
        transform: translateY(-2px) !important;
        border-color: #38bdf8 !important;
        box-shadow: 0 6px 18px rgba(56, 189, 248, 0.35) !important;
    }

    /* 🌟 사이드바 파이프라인 실시간 모니터링 애니메이션 (Live Radar & Pulsing) */
    @keyframes live-pulse {
        0% { box-shadow: 0 0 0 0 rgba(34, 197, 94, 0.7); }
        70% { box-shadow: 0 0 0 7px rgba(34, 197, 94, 0); }
        100% { box-shadow: 0 0 0 0 rgba(34, 197, 94, 0); }
    }
    @keyframes live-pulse-amber {
        0% { box-shadow: 0 0 0 0 rgba(245, 158, 11, 0.7); }
        70% { box-shadow: 0 0 0 7px rgba(245, 158, 11, 0); }
        100% { box-shadow: 0 0 0 0 rgba(245, 158, 11, 0); }
    }
    @keyframes live-glow {
        0%, 100% { opacity: 1; filter: drop-shadow(0 0 5px #22c55e); }
        50% { opacity: 0.65; filter: drop-shadow(0 0 2px #22c55e); }
    }
    .pipeline-pulse-dot {
        display: inline-block;
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background-color: #22c55e;
        margin-right: 8px;
        flex-shrink: 0;
        animation: live-pulse 1.8s infinite;
    }
    .pipeline-pulse-dot.amber {
        background-color: #f59e0b;
        animation: live-pulse-amber 2.2s infinite;
    }
    .live-badge-radar {
        display: inline-flex;
        align-items: center;
        gap: 5px;
        background: rgba(34, 197, 94, 0.12);
        border: 1px solid rgba(34, 197, 94, 0.4);
        color: #4ade80;
        font-size: 11px;
        font-weight: 800;
        padding: 2px 8px;
        border-radius: 12px;
        animation: live-glow 2s infinite ease-in-out;
    }

    /* 🌟 포렌식 증적 및 Zero Trust 액션 카드 정렬 고도화 (줄맞춤 & 가독성) */
    .zt-action-card {
        display: flex;
        align-items: flex-start;
        gap: 12px;
        background: #0d1a2d;
        border: 1px solid #1c3252;
        border-radius: 9px;
        padding: 11px 14px;
        margin-bottom: 9px;
        word-break: keep-all;
        line-height: 1.55;
    }
    .zt-action-badge {
        background: #1e3a8a;
        color: #60a5fa;
        font-size: 12px;
        font-weight: 800;
        width: 22px;
        height: 22px;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        flex-shrink: 0;
        margin-top: 2px;
    }
    .evidence-item {
        background: #0d1a2d;
        border: 1px solid #1c3252;
        border-radius: 8px;
        padding: 10px 14px;
        margin-bottom: 8px;
        font-size: 13px;
        color: #e2e8f0;
        word-break: keep-all;
        line-height: 1.55;
        display: flex;
        align-items: flex-start;
        gap: 8px;
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
    st.session_state.nav_radio = "종합 관제"

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
    <div style="padding: 10px 0 10px 0;">
        <h2 style="color: #f5f7fb; margin:0; font-size:22px; font-weight:700;">
            {tooltip("🛡️", "NexusGuard XDR Platform", "이기종 다차원 로그 상관분석 & 섀도우 AI 거버넌스 자동화 시스템")} NexusGuard
        </h2>
    </div>
    """, unsafe_allow_html=True)

    menu_options = ["종합 관제", "킬체인 분석", "AI·IT 거버넌스", "중앙 서버 파이프 라인"]
    if "nav_radio" not in st.session_state or st.session_state.nav_radio not in menu_options:
        st.session_state.nav_radio = "종합 관제"

    menu = st.radio(
        "네비게이션",
        menu_options,
        key="nav_radio",
        label_visibility="collapsed"
    )

    st.markdown("---")
    with st.expander("🧪 실시간 시뮬레이터", expanded=True):
        st.markdown("<div style='font-size:12px; color:#cbd5e1; margin-bottom:4px;'>사내 Shadow AI 기밀 유출 킬체인을 단계별로 실시간 시뮬레이션합니다.</div>", unsafe_allow_html=True)
        st.markdown("<div style='font-size:11px; color:#38bdf8; margin-bottom:10px;'>👥 <b>팀원 실제 로그 연동 모드</b> (NexusGuardAgent.exe & activity.log)</div>", unsafe_allow_html=True)
        col_s1, col_s2 = st.columns(2)
        with col_s1:
            btn_watch = st.button("👁️ 1단계\n선제 감시", use_container_width=True, help="팀원(kim, User)의 기밀 DB 조회 + 미승인 SaaS/AI 접속 포착 -> WATCH 선제 승격")
        with col_s2:
            btn_high = st.button("🚨 2단계\n유출 확정", use_container_width=True, help="WATCH 대상자의 대용량 외부 전송 포착 -> HIGH Incident 즉시 확정")
            
        col_s3, col_s4 = st.columns(2)
        with col_s3:
            btn_heal = st.button("⏱️ 3단계\n오탐 해제", use_container_width=True, help="전송 없이 30분 경과 -> NORMAL 상태로 자가 치유")
        with col_s4:
            btn_reset = st.button("🔄 초기화\n시뮬 리셋", use_container_width=True, help="시뮬레이션 데이터 초기화")

        # Railway 수집 상태 세션 변수 사전 초기화
        from nexusguard.collectors.team_collector import set_railway_collection_enabled, is_railway_collection_enabled
        if "railway_collection_active" not in st.session_state:
            st.session_state["railway_collection_active"] = False
        if "sb_railway_toggle" not in st.session_state:
            st.session_state["sb_railway_toggle"] = st.session_state["railway_collection_active"]
        if "view_railway_collection_toggle" not in st.session_state:
            st.session_state["view_railway_collection_toggle"] = st.session_state["railway_collection_active"]

        # 🌟 현재 '중앙 서버 파이프 라인' 페이지가 아닐 때만 사이드바 수집 제어 박스 표시
        if menu != "중앙 서버 파이프 라인":
            st.markdown("<div style='height:6px;'></div>", unsafe_allow_html=True)
            with st.container(border=True):
                st.markdown("<div style='font-size:12px; font-weight:700; color:#38bdf8; margin-bottom:4px;'>🌐 Railway 실시간 수집</div>", unsafe_allow_html=True)

                def _on_sb_railway_toggle():
                    val = st.session_state.get("sb_railway_toggle", False)
                    st.session_state["railway_collection_active"] = val
                    st.session_state["view_railway_collection_toggle"] = val
                    set_railway_collection_enabled(val)

                sb_railway_active = st.toggle(
                    "실시간 로그 수집 가동", 
                    value=st.session_state.get("railway_collection_active", False),
                    key="sb_railway_toggle", 
                    on_change=_on_sb_railway_toggle, 
                    help="Railway 실시간 로그 수집을 켜거나 끕니다."
                )
                set_railway_collection_enabled(sb_railway_active)
                if st.button("🔄 최신 로그 즉시 동기화", disabled=not sb_railway_active, use_container_width=True, key="btn_sb_sync_now", help="Railway 중앙 서버에서 최신 에이전트 수집 로그를 즉시 갱신합니다."):
                    from nexusguard.collectors.team_collector import fetch_railway_events
                    r_logs = fetch_railway_events(timeout=5, force=True)
                    st.toast(f"🔄 Railway 중앙 서버에서 최신 {len(r_logs)}개 에이전트 로그를 동기화했습니다.", icon="🌐")
                    st.rerun()

    from nexusguard.collectors.team_collector import get_team_sim_scenarios
    SIM_SCENARIOS = get_team_sim_scenarios()

    if btn_watch:
        import random
        # 현재 WATCH 상태가 아닌 시나리오를 우선 선별
        active_watch_users = [u.get("user") for u in ctx.correlation_engine.get_watch_users() if u.get("state") == "WATCH"]
        available_scenarios = [s for s in SIM_SCENARIOS if s["user"] not in active_watch_users]
        sc = random.choice(available_scenarios) if available_scenarios else random.choice(SIM_SCENARIOS)
        st.session_state["last_sim_scenario"] = sc
        
        now = datetime.utcnow()
        ev1 = SecurityEvent(
            event_id=f"EVT-SIM-DB-{int(now.timestamp())}-{random.randint(10,99)}",
            timestamp=now,
            log_source=LogSource.DB,
            actor=Actor(user_id=sc["user"], src_ip=sc["ip"]),
            target=Target(dst_ip="10.0.0.30", dst_port=3306),
            action=EventAction.SELECT,
            payload=PayloadMetadata(table_name=sc["table"], query_string=sc["query"])
        )
        ev2 = SecurityEvent(
            event_id=f"EVT-SIM-DNS-{int(now.timestamp())}-{random.randint(10,99)}",
            timestamp=now + timedelta(seconds=5),
            log_source=LogSource.DNS,
            actor=Actor(user_id=sc["user"], src_ip=sc["ip"]),
            target=Target(domain=sc["service"]),
            action=EventAction.QUERY,
            payload=PayloadMetadata(category=sc["category"])
        )
        ctx.correlation_engine.update_user_risk(ev1)
        ctx.correlation_engine.update_user_risk(ev2)
        # 1단계 선제 감시 인시던트 생성 (WATCH 카운트 및 드롭다운 실시간 연동)
        watch_inc = ctx.correlation_engine.create_watch_incident(sc["user"], sc)
        st.session_state.selected_incident_id = watch_inc.incident_id
        st.toast(f"⚡ [1단계 선제 감시] '{sc['user']}'({sc['name']}) WATCH 승격! ({sc['data_desc']} 접근 포착)", icon="👁️")
        st.rerun()

    if btn_high:
        now = datetime.utcnow()
        active_watch_list = [u for u in ctx.correlation_engine.get_watch_users() if u.get("state") == "WATCH"]
        target_user = None
        sc = None
        if active_watch_list:
            target_user = active_watch_list[0]["user"]
            for s in SIM_SCENARIOS:
                if s["user"] == target_user:
                    sc = s
                    break
        if not sc:
            sc = st.session_state.get("last_sim_scenario", SIM_SCENARIOS[0])
            # WATCH 상태가 아니라면 1단계를 선행 처리 후 2단계 전이
            ev_pre1 = SecurityEvent(
                event_id=f"EVT-PRE-DB-{int(now.timestamp())}",
                timestamp=now - timedelta(minutes=2),
                log_source=LogSource.DB,
                actor=Actor(user_id=sc["user"], src_ip=sc["ip"]),
                target=Target(dst_ip="10.0.0.30", dst_port=3306),
                action=EventAction.SELECT,
                payload=PayloadMetadata(table_name=sc["table"], query_string=sc["query"])
            )
            ev_pre2 = SecurityEvent(
                event_id=f"EVT-PRE-DNS-{int(now.timestamp())}",
                timestamp=now - timedelta(minutes=1),
                log_source=LogSource.DNS,
                actor=Actor(user_id=sc["user"], src_ip=sc["ip"]),
                target=Target(domain=sc["service"]),
                action=EventAction.QUERY,
                payload=PayloadMetadata(category=sc["category"])
            )
            ctx.correlation_engine.update_user_risk(ev_pre1)
            ctx.correlation_engine.update_user_risk(ev_pre2)

        ev3 = SecurityEvent(
            event_id=f"EVT-SIM-FW-{int(now.timestamp())}",
            timestamp=now,
            log_source=LogSource.FIREWALL,
            actor=Actor(user_id=sc["user"], src_ip=sc["ip"]),
            target=Target(domain=sc["dst_domain"], dst_port=443),
            action=EventAction.ALLOW,
            payload=PayloadMetadata(bytes_sent=sc["bytes"])
        )
        ctx.correlation_engine.update_user_risk(ev3)
        # 해당 사용자의 기존 미완료 WATCH 인시던트 정리
        for inc_id, inc in list(ctx.correlation_engine.incidents.items()):
            if sc["user"] in inc.title and inc.severity == Severity.MEDIUM:
                inc.status = IncidentStatus.RESOLVED
                ctx.correlation_engine.store.save_incident(inc)
        # 생성된 최신 HIGH 인시던트로 자동 포커스
        for inc in ctx.correlation_engine.get_all_incidents():
            if (sc["user"] in inc.title or sc["user"] in inc.actor) and inc.severity == Severity.HIGH:
                st.session_state.selected_incident_id = inc.incident_id
                break
        st.toast(f"🚨 [2단계 유출 확정] '{sc['user']}'({sc['name']}) 외부 {sc['bytes']/(1024*1024):.1f}MB 전송 포착! HIGH Incident 생성 완료!", icon="🚨")
        st.rerun()

    if btn_heal:
        now = datetime.utcnow()
        active_watch_list = [u for u in ctx.correlation_engine.get_watch_users() if u.get("state") == "WATCH"]
        if active_watch_list:
            heal_user = active_watch_list[0]["user"]
        else:
            heal_user = "choi_intern"
        ctx.correlation_engine.store.upsert_risk(
            user=heal_user,
            state="NORMAL",
            score=15,
            reasons=["30분 경과: 외부 데이터 전송 행위 없음 (오탐 자동 해제)"],
            expires_at=now + timedelta(hours=1)
        )
        ctx.correlation_engine.store.append_history(
            user=heal_user,
            from_state="WATCH",
            to_state="NORMAL",
            reason="30분 만료(TTL)로 인한 정상(NORMAL) 자가 치유"
        )
        # 기존 미완료 WATCH 인시던트 종료
        for inc_id, inc in list(ctx.correlation_engine.incidents.items()):
            if heal_user in inc.title and inc.severity == Severity.MEDIUM:
                inc.status = IncidentStatus.RESOLVED
                ctx.correlation_engine.store.save_incident(inc)
        # 3단계 오탐 해제 인시던트 생성 (NORMAL 카운트 및 드롭다운 실시간 연동)
        heal_inc = ctx.correlation_engine.create_heal_incident(heal_user)
        st.session_state.selected_incident_id = heal_inc.incident_id
        st.toast(f"⏱️ [오탐 자동 해제] 30분간 전송이 없었던 '{heal_user}'이(가) NORMAL로 자가 치유되었습니다.", icon="⏱️")
        st.rerun()

    if btn_reset:
        ctx.correlation_engine.store.clear_all()
        ctx.correlation_engine.incidents.clear()
        ctx.correlation_engine._init_mock_incidents()
        st.session_state.selected_incident_id = "INC-001"
        st.toast("🔄 시뮬레이션 상태 및 인시던트가 초기화되었습니다.", icon="🔄")
        st.rerun()

    st.markdown("---")
    
    # Gemini AI 상태 판별
    import os
    from pathlib import Path
    try:
        from dotenv import load_dotenv
        load_dotenv(Path(__file__).resolve().parent.parent.parent / ".env")
    except Exception:
        pass

    if "gemini_api_key" not in st.session_state:
        st_sec_gemini = ""
        try:
            if hasattr(st, "secrets") and "GEMINI_API_KEY" in st.secrets:
                st_sec_gemini = str(st.secrets["GEMINI_API_KEY"])
        except Exception:
            pass
        st.session_state["gemini_api_key"] = os.environ.get("GEMINI_API_KEY", st_sec_gemini)

    has_gemini_key = bool(st.session_state.get("gemini_api_key"))
    use_local_ai = st.session_state.get("use_local_ai", True)

    with st.expander("🔑 Gemini AI 엔진 연동 설정", expanded=False):
        st.markdown("<div style='font-size:12px; color:#cbd5e1; margin-bottom:6px;'>미등록 외부 SaaS 및 Shadow AI 도메인을 자동 분류하고 데이터 재학습 위험도를 실시간 진단하는 AI 보강(Enrichment) 엔진입니다.</div>", unsafe_allow_html=True)
        key_input = st.text_input("Gemini API Key", type="password", value=st.session_state.get("gemini_api_key", ""), placeholder="AIzaSy... 또는 AQ.Ab... (Google AI Studio)", help="Google AI Studio에서 발급받은 API 키가 자동 적용되어 실시간 Gemini 3.6 / 2.5 Flash 모델이 가동됩니다.")
        if key_input != st.session_state.get("gemini_api_key", ""):
            st.session_state["gemini_api_key"] = key_input
            if key_input:
                os.environ["GEMINI_API_KEY"] = key_input
            has_gemini_key = bool(key_input)
        enable_local = st.toggle("로컬 AI 지능형 엔진 활성화", value=use_local_ai, help="API 키가 없을 때도 패턴 인식 휴리스틱 AI로 상시 가동합니다.")
        st.session_state["use_local_ai"] = enable_local
        use_local_ai = enable_local

    if has_gemini_key:
        gemini_status_line = '<div style="color: #62d487; font-size:12px; margin-top:5px; display:flex; align-items:center;"><span class="pipeline-pulse-dot"></span> Gemini AI 판별 모듈 가동 중 (Cloud 3.6/2.5)</div>'
    elif use_local_ai:
        gemini_status_line = '<div style="color: #62d487; font-size:12px; margin-top:5px; display:flex; align-items:center;"><span class="pipeline-pulse-dot"></span> Gemini AI 판별 모듈 가동 중 (로컬 AI)</div>'
    else:
        gemini_status_line = '<div style="color: #fbbf24; font-size:12px; margin-top:5px; display:flex; align-items:center;"><span class="pipeline-pulse-dot amber"></span> Gemini AI 판별 모듈 대기 (키 미등록)</div>'

    railway_is_on = st.session_state.get("railway_collection_active", False)
    if railway_is_on:
        railway_status_line = '<div style="color: #62d487; font-size:12px; margin-top:6px; display:flex; align-items:center;"><span class="pipeline-pulse-dot"></span> 팀원 Agent & Railway 수집 중 (LIVE)</div>'
    else:
        railway_status_line = '<div style="color: #94a3b8; font-size:12px; margin-top:6px; display:flex; align-items:center;"><span class="pipeline-pulse-dot" style="background:#64748b; box-shadow:none;"></span> Railway 수집 일시정지 (OFF)</div>'

    st.markdown(f"""
    <div style="background: #111e30; padding: 14px; border-radius: 10px; border: 1px solid #1e3352; box-shadow: 0 4px 12px rgba(0,0,0,0.3);">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
            <span style="font-size:12px; font-weight:700; color:#9fb0c8;">
                {tooltip("⚙️", "시스템 데몬 상태", "백그라운드에서 실행 중인 4대 핵심 파이프라인 데몬의 헬스체크 상태입니다.")} 파이프라인 상태 모니터링
            </span>
            <span class="live-badge-radar">
                <span class="pipeline-pulse-dot"></span>LIVE
            </span>
        </div>
        {railway_status_line}
        <div style="color: #62d487; font-size:12px; margin-top:5px; display:flex; align-items:center;">
            <span class="pipeline-pulse-dot"></span> 이기종 로그 정규화 정상
        </div>
        <div style="color: #62d487; font-size:12px; margin-top:5px; display:flex; align-items:center;">
            <span class="pipeline-pulse-dot"></span> 듀얼 상관분석 엔진 가동 중
        </div>
        {gemini_status_line}
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


if menu == "종합 관제":
    st.markdown("""
    <div class="dashboard-title-box">
        <h1 class="dashboard-title">
            Dashboard <span class="dashboard-info-icon" title="마우스를 올리면 시스템 설명이 표시됩니다">ℹ️</span>
        </h1>
        <div class="dashboard-title-tooltip">
            🛡️ 실시간 이기종 로그 연계 침해사고 재구성 및 내부 데이터 거버넌스 모니터링 (Zero Trust XDR)
        </div>
    </div>
    """, unsafe_allow_html=True)

    # 위험도별 인시던트 목록 분할 (WATCH: MEDIUM / NORMAL: LOW)
    all_incident_ids = [inc.incident_id for inc in incidents]
    crit_high_ids = [inc.incident_id for inc in incidents if inc.severity in [Severity.CRITICAL, Severity.HIGH]]
    watch_ids = [inc.incident_id for inc in incidents if inc.severity == Severity.MEDIUM]
    normal_ids = [inc.incident_id for inc in incidents if inc.severity == Severity.LOW]

    # 기본 선택 인시던트 유효성 검증
    if "selected_incident_id" not in st.session_state or st.session_state.selected_incident_id not in all_incident_ids:
        st.session_state.selected_incident_id = all_incident_ids[0]

    # 위험도 우선순위 정렬: CRITICAL -> HIGH -> MEDIUM (WATCH) -> LOW (NORMAL) (동일 등급 내 점수 내림차순)
    sev_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
    sorted_incidents = sorted(
        incidents,
        key=lambda x: (sev_order.get(x.severity, 99), -x.score)
    )
    sorted_incident_ids = [inc.incident_id for inc in sorted_incidents]

    # 🌟 [단일 통합 드롭다운 포맷터] 위험도별 색상 및 기호로 시인성 극대화 (WATCH: 🟡 / NORMAL: 🟢)
    def format_unified_incident(inc_id: str) -> str:
        inc = ctx.correlation_engine.get_incident(inc_id)
        if not inc:
            return inc_id
        if inc.severity == Severity.CRITICAL:
            badge = f"🔴 [CRITICAL {inc.score}점]"
        elif inc.severity == Severity.HIGH:
            badge = f"🔴 [HIGH {inc.score}점]"
        elif inc.severity == Severity.MEDIUM:
            badge = f"🟡 [WATCH {inc.score}점]"
        else:
            badge = f"🟢 [NORMAL {inc.score}점]"
        return f"{badge}  {inc.incident_id}  |  {inc.title}"

    cur_idx = sorted_incident_ids.index(st.session_state.selected_incident_id) if st.session_state.selected_incident_id in sorted_incident_ids else 0

    def on_select_unified():
        st.session_state.selected_incident_id = st.session_state.sel_unified_incident

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

    # 📈 실시간 2단계 상태 머신 감사 이력 (주식창 스타일 항시 노출 뷰 - 확대)
    hist = ctx.correlation_engine.store.get_risk_history(25)
    st.markdown("""
    <div style="background: #091322; border: 1.5px solid #1e3a5f; border-radius: 10px; padding: 14px 18px 8px 18px; margin-bottom: 16px; box-shadow: 0 4px 14px rgba(0,0,0,0.35);">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 10px;">
            <span style="font-weight:800; font-size:14px; color:#38bdf8; display:flex; align-items:center; gap:6px;">
                📈 실시간 보안 상태 감사 트레일 (Live Security Ticker · SQLite Audit)
            </span>
            <span style="font-size:11px; color:#94a3b8; background:rgba(30,58,138,0.4); padding:3px 8px; border-radius:4px; border:1px solid #1e40af;">실시간 2단계 상태 전이 영구 보관</span>
        </div>
    """, unsafe_allow_html=True)
    if hist:
        df_hist = pd.DataFrame(hist)[["at", "user", "from_state", "to_state", "reason"]]
        df_hist.columns = ["일시 (UTC)", "대상 계정/호스트", "이전 상태", "전이 상태", "판정 사유"]
        st.dataframe(df_hist, use_container_width=True, height=270)
    else:
        st.caption("💡 현재 기록된 상태 전이 이력이 없습니다. 좌측 사이드바 시뮬레이터를 통해 이벤트를 주입해보세요.")
    st.markdown("</div>", unsafe_allow_html=True)

    # 🌟 [상단 분계선] 3대 KPI 카드 위 분계선
    st.markdown('<hr style="border: 0; border-top: 1.5px solid #1e3a5f; margin: 18px 0 16px 0;">', unsafe_allow_html=True)

    # 3대 위험도별 KPI 카드 (CRITICAL/HIGH, WATCH, NORMAL) - 색상은 유지하고 문구 치환 (WATCH: 🟡 주황, NORMAL: 🟢 초록)
    crit_high_count = len(crit_high_ids)
    watch_count = len(watch_ids)
    normal_count = len(normal_ids)

    kpi1, kpi2, kpi3 = st.columns(3)

    with kpi1:
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-title critical-text">
                {tooltip("🚨", "CRITICAL / HIGH 긴급 경보", "즉각적인 격리 또는 차단이 요구되는 활성 공격 및 기밀 유출 사건입니다.")} CRITICAL / HIGH
            </div>
            <div class="kpi-value critical-text">{crit_high_count}</div>
            <div class="kpi-sub">긴급 대응 필요 침해 킬체인</div>
        </div>
        """, unsafe_allow_html=True)

    with kpi2:
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-title medium-text">
                {tooltip("👁️", "WATCH 사전 관찰", "위험 행위 징후 포착에 따른 선제적 모니터링 추적 단계입니다.")} WATCH
            </div>
            <div class="kpi-value medium-text">{watch_count}</div>
            <div class="kpi-sub">사전 관찰 및 잠재 이상 추적</div>
        </div>
        """, unsafe_allow_html=True)

    with kpi3:
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-title low-text">
                {tooltip("⚖️", "NORMAL 정상/주의", "일반 업무 활동 및 경미한 이상 징후 모니터링 단계입니다.")} NORMAL
            </div>
            <div class="kpi-value low-text">{normal_count}</div>
            <div class="kpi-sub">일반 활동 및 모니터링 단계</div>
        </div>
        """, unsafe_allow_html=True)

    # 🌟 [하단 분계선] 3대 KPI 카드 아래 분계선
    st.markdown('<hr style="border: 0; border-top: 1.5px solid #1e3a5f; margin: 16px 0 20px 0;">', unsafe_allow_html=True)

    # 🌟 [단일 통합 카드 형식 인시던트 선택기] 건수 표시 제거, 색상 가이드만 유지, 단일 카드로 묶음
    with st.container(border=True):
        st.markdown("""
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 8px;">
            <span style="font-weight:700; font-size:15px; color:#60a5fa; display:flex; align-items:center; gap:6px;">
                🎯 분석 대상 인시던트 통합 선택
            </span>
            <span style="font-size:13px; color:#cbd5e1; background:rgba(30,58,138,0.3); padding:4px 12px; border-radius:20px; border:1px solid #1e40af;">
                🔴 CRITICAL / HIGH &nbsp;·&nbsp; 🟡 WATCH &nbsp;·&nbsp; 🟢 NORMAL
            </span>
        </div>
        """, unsafe_allow_html=True)
        st.selectbox(
            "인시던트 목록",
            options=sorted_incident_ids,
            index=cur_idx,
            format_func=format_unified_incident,
            key="sel_unified_incident",
            on_change=on_select_unified,
            label_visibility="collapsed"
        )

    # 선택된 분석 대상 인시던트 종합 정보 카드 (위험도별 동적 색상 및 테마 반영)
    selected_inc = ctx.correlation_engine.get_incident(st.session_state.selected_incident_id)

    # 🌟 사용자 요청: 위험도 색상을 카드 테두리, 발광, 텍스트, 뱃지 전반에 반영하여 시인성 향상
    if selected_inc.severity == Severity.CRITICAL:
        card_theme = {
            "border": "#ef4444",
            "border_left": "#f87171",
            "glow": "rgba(239, 68, 68, 0.35)",
            "bg": "linear-gradient(135deg, #1f0b12 0%, #290f1b 50%, #151a2d 100%)",
            "header_color": "#f87171",
            "header_label": "🚨 [치명적 침해사고 긴급 격리 대상] 인시던트 종합 정보",
            "dot_glow": "#ef4444",
            "badge": '<span class="badge badge-critical" style="font-size:13px; padding:5px 12px; background:#dc2626; color:#ffffff; font-weight:800; border-radius:6px;">CRITICAL (치명)</span>',
            "score_color": "#ff4d61",
            "actor_color": "#fca5a5",
            "target_color": "#f87171",
            "inner_border": "rgba(239, 68, 68, 0.3)",
        }
    elif selected_inc.severity == Severity.HIGH:
        card_theme = {
            "border": "#f43f5e",
            "border_left": "#fb7185",
            "glow": "rgba(244, 63, 94, 0.35)",
            "bg": "linear-gradient(135deg, #1c0a13 0%, #260e1c 50%, #151a2d 100%)",
            "header_color": "#fb7185",
            "header_label": "🚨 [고위험 유출/침해 대응 대상] 인시던트 종합 정보",
            "dot_glow": "#f43f5e",
            "badge": '<span class="badge badge-high" style="font-size:13px; padding:5px 12px; background:#e11d48; color:#ffffff; font-weight:800; border-radius:6px;">HIGH (고위험)</span>',
            "score_color": "#ff758f",
            "actor_color": "#fecdd3",
            "target_color": "#fb7185",
            "inner_border": "rgba(244, 63, 94, 0.3)",
        }
    elif selected_inc.severity == Severity.MEDIUM:
        card_theme = {
            "border": "#f59e0b",
            "border_left": "#fbbf24",
            "glow": "rgba(245, 158, 11, 0.35)",
            "bg": "linear-gradient(135deg, #1c1507 0%, #261d0a 50%, #121927 100%)",
            "header_color": "#fbbf24",
            "header_label": "👁️ [WATCH 단계 선제적 감시 대상] 인시던트 종합 정보",
            "dot_glow": "#f59e0b",
            "badge": '<span class="badge badge-medium" style="font-size:13px; padding:5px 12px; background:#d97706; color:#ffffff; font-weight:800; border-radius:6px;">WATCH</span>',
            "score_color": "#fbbf24",
            "actor_color": "#fde68a",
            "target_color": "#f59e0b",
            "inner_border": "rgba(245, 158, 11, 0.3)",
        }
    else:  # LOW
        card_theme = {
            "border": "#10b981",
            "border_left": "#34d399",
            "glow": "rgba(16, 185, 129, 0.35)",
            "bg": "linear-gradient(135deg, #091a13 0%, #0d261d 50%, #0d1927 100%)",
            "header_color": "#34d399",
            "header_label": "⚖️ [NORMAL 단계 정상/모니터링 대상] 인시던트 종합 정보",
            "dot_glow": "#10b981",
            "badge": '<span class="badge badge-low" style="font-size:13px; padding:5px 12px; background:#059669; color:#ffffff; font-weight:800; border-radius:6px;">NORMAL</span>',
            "score_color": "#34d399",
            "actor_color": "#a7f3d0",
            "target_color": "#10b981",
            "inner_border": "rgba(16, 185, 129, 0.3)",
        }

    st.markdown(f"""
    <div style="background: {card_theme['bg']}; border: 1.5px solid {card_theme['border']}; border-left: 6px solid {card_theme['border_left']}; border-radius: 12px; padding: 22px 28px; margin-top: 14px; margin-bottom: 8px; box-shadow: 0 6px 20px {card_theme['glow']};">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
            <div style="font-size: 13px; font-weight: 800; color: {card_theme['header_color']}; letter-spacing: 0.8px; text-transform: uppercase; display: flex; align-items: center; gap: 8px;">
                <span style="display:inline-block; width:9px; height:9px; border-radius:50%; background:{card_theme['dot_glow']}; box-shadow:0 0 10px {card_theme['dot_glow']};"></span>
                {card_theme['header_label']}
            </div>
            <div style="font-size: 13px; color: #94a3b8;">
                위협 분류: <b style="color: {card_theme['header_color']}; font-size:14px; margin-left:4px;">{selected_inc.category.value}</b>
            </div>
        </div>
        <div style="display: flex; align-items: center; gap: 14px; margin-bottom: 14px; flex-wrap: wrap;">
            <span style="font-size: 24px; font-weight: 900; color: #ffffff; letter-spacing: -0.5px;">{selected_inc.incident_id}</span>
            {card_theme['badge']}
            <span style="font-size: 17px; font-weight: 700; color: #f8fafc; line-height: 1.4;">{selected_inc.title}</span>
        </div>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 14px; background: rgba(7, 17, 31, 0.7); padding: 14px 20px; border-radius: 10px; border: 1px solid {card_theme['inner_border']};">
            <div style="font-size: 13px; color: #94a3b8; display:flex; align-items:center;">
                <span style="font-size:15px; margin-right:6px;">📍</span> <b>공격 발원지:</b> <span style="color:{card_theme['actor_color']}; font-weight:700; font-size:14px; margin-left:6px;">{selected_inc.actor}</span>
            </div>
            <div style="font-size: 13px; color: #94a3b8; display:flex; align-items:center;">
                <span style="font-size:15px; margin-right:6px;">🎯</span> <b>타깃 자산:</b> <span style="color:{card_theme['target_color']}; font-weight:700; font-size:14px; margin-left:6px;">{selected_inc.target_asset}</span>
            </div>
            <div style="font-size: 13px; color: #94a3b8; display:flex; align-items:center;">
                <span style="font-size:15px; margin-right:6px;">⚡</span> <b>상관분석 점수:</b> <span style="color:{card_theme['score_color']}; font-weight:800; font-size:16px; margin-left:6px;">{selected_inc.score}점</span>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # ⚡ SOAR 원클릭 긴급 보안 조치 및 관제 대응
    st.markdown("<hr style='border:none; border-top:1.5px solid #1e3a5f; margin:20px 0 16px 0;'>", unsafe_allow_html=True)
    
    soar_header = f"""
    <div class="box-title" style="display:flex; justify-content:space-between; align-items:center;">
        <span>{tooltip("⚡", "SOAR 원클릭 자동 대응", "보안관제 요원이 클릭 한 번으로 방화벽 차단 룰 배포 및 세션 격리를 수행할 수 있는 자동화 조치입니다.")} ⚡ SOAR 원클릭 긴급 보안 조치 및 관제 대응</span>
        <span style="font-size:12px; font-weight:normal; color:#94a3b8;">분석 대상: <b style="color:#38bdf8;">{selected_inc.incident_id}</b> ({selected_inc.severity.value}) · 신뢰 점수: <b style="color:#ff5b6b;">{selected_inc.score}점</b></span>
    </div>
    """
    st.markdown(soar_header, unsafe_allow_html=True)

    soar_col1, soar_col2, soar_col3, soar_col4 = st.columns(4)
    with soar_col1:
        if st.button("🚨 방화벽 차단 룰 즉시 배포", key="btn_fw", use_container_width=True, help="해당 공격 발원지 IP 및 C2 목적지를 경계 방화벽 차단 목록에 영구 추가합니다."):
            st.success("✅ iptables / 방화벽 차단 정책이 즉시 배포되었습니다.")
    with soar_col2:
        if st.button("🔒 활성 계정 세션 즉시 만료", key="btn_revoke", use_container_width=True, help="침해된 계정의 모든 SSO 세션 및 토큰을 무효화합니다."):
            st.success("✅ 해당 계정의 모든 SSO 세션이 강제 종료되었습니다.")
    with soar_col3:
        if st.button("📢 Slack 보안팀 긴급 전파", key="btn_slack", use_container_width=True, help="Slack #incident-critical 채널로 경보 웹훅을 전파합니다."):
            st.info("📨 Slack #incident-alert 채널로 웹훅 전파 완료!")
    with soar_col4:
        st.button(
            "🔍 킬체인 심층 분석 바로가기 ➔",
            key="btn_jump_kc",
            on_click=navigate_to,
            args=("킬체인 분석", selected_inc.incident_id),
            use_container_width=True,
            help="해당 인시던트의 네트워크 토폴로지 맵 및 상세 킬체인 분석 탭으로 이동합니다."
        )


# ==========================================
# VIEW 2: 킬체인 분석 (Lateral Movement)
# ==========================================
elif menu == "킬체인 분석":
    top_col1, top_col2 = st.columns([7, 3])
    with top_col1:
        st.markdown("<h2>🎯 외부 침투 및 침해사고 킬체인(Lateral Movement) 심층 분석</h2>", unsafe_allow_html=True)
    with top_col2:
        st.markdown("<div style='margin-top: 10px;'></div>", unsafe_allow_html=True)
        st.button(
            "⬅️ 종합 관제로 돌아가기",
            on_click=navigate_to,
            args=("종합 관제",),
            use_container_width=True
        )

    incident_ids = [inc.incident_id for inc in incidents]
    curr_target_id = st.session_state.get("selected_incident_id", incidents[0].incident_id)
    if curr_target_id not in incident_ids:
        curr_target_id = incident_ids[0]

    def format_inc_option(inc_id: str) -> str:
        inc = ctx.correlation_engine.get_incident(inc_id)
        if not inc:
            return inc_id
        sev_badge = {
            Severity.CRITICAL: "🔴 [CRITICAL]",
            Severity.HIGH: "🔴 [HIGH]",
            Severity.MEDIUM: "🟡 [WATCH]",
            Severity.LOW: "🟢 [NORMAL]"
        }.get(inc.severity, "⚪")
        return f"{sev_badge} {inc.incident_id} | {inc.title}"

    def on_killchain_dropdown():
        st.session_state.selected_incident_id = st.session_state.killchain_tab_selectbox

    st.session_state.killchain_tab_selectbox = st.session_state.selected_incident_id

    sel_tab_id = st.selectbox(
        "🔎 분석 대상 인시던트 선택",
        options=incident_ids,
        format_func=format_inc_option,
        key="killchain_tab_selectbox",
        on_change=on_killchain_dropdown
    )

    target_inc = ctx.correlation_engine.get_incident(st.session_state.selected_incident_id)

    st.info(f"**[{target_inc.incident_id}] {target_inc.title}**\n\n{target_inc.summary}")

    # 🌐 침해사고 네트워크 토폴로지 맵
    map_title = f"""
    <div class="box-title" style="display:flex; justify-content:space-between; align-items:center;">
        <span>{tooltip("🌐", "네트워크 토폴로지 맵", "선택된 인시던트의 발원지, 경유지, 타깃 자산 간의 통신 포트와 공격 이동 경로를 실시간 시각화합니다. 마우스 휠로 확대/축소하고 드래그하여 지도를 자유롭게 이동할 수 있습니다.")} 네트워크 토폴로지 맵 (Network Map)</span>
        <span style="font-size:12px; font-weight:normal; color:#64748b;">🔍 마우스 휠 확대/축소 & 드래그 이동 지원</span>
    </div>
    """
    st.markdown(map_title, unsafe_allow_html=True)
    st.markdown(f"<div style='font-size:13px; color:#9fb0c8; margin-bottom:10px;'>현재 분석 대상: <b style='color:#38bdf8;'>{target_inc.incident_id}</b> ({target_inc.category.value}) — <b>{target_inc.title}</b></div>", unsafe_allow_html=True)

    raw_svg = generate_dynamic_network_svg(target_inc)
    render_interactive_map(raw_svg)

    # 🔍 인시던트 상세 타임라인 & 상관분석 판단 근거 & Zero Trust 대응
    st.markdown("<hr style='border:none; border-top:1.5px solid #1c2e47; margin:24px 0 20px 0;'>", unsafe_allow_html=True)
    
    col_left, col_right = st.columns([1, 1])
    
    with col_left:
        st.markdown(f"""
        <div class="box-title">
            {tooltip("⏱️", "공격 시퀀스 순서", "공격자가 내부망에 침투하여 목적을 달성하기까지의 행위 순서입니다.")} 공격 행위 타임라인 (Attack Sequence)
        </div>
        """, unsafe_allow_html=True)
        # 홉(Hop) 기반 타임라인 자동 생성
        steps_html_parts = []
        for idx, h in enumerate(target_inc.network_hops):
            steps_html_parts.append(f'<span class="timeline-step">{idx+1}. {h.from_node} ➔ {h.to_node} (:{h.port})</span>')
        steps_html = f'<div style="margin-top:8px; margin-bottom:20px; display:flex; flex-wrap:wrap; gap:8px;">{" ".join(steps_html_parts)}</div>'
        st.markdown(steps_html, unsafe_allow_html=True)

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

    with col_right:
        st.markdown(f"""
        <div class="box-title">
            {tooltip("🛡️", "상관분석 판단 근거", "서로 다른 이기종 로그를 단일 공격으로 결합한 수학적/규칙적 판단 근거입니다.")} 상관분석 판단 근거 (Explainable Evidence)
        </div>
        """, unsafe_allow_html=True)
        for ev in target_inc.evidences:
            st.markdown(f"""
            <div class="evidence-item">
                <span style="color:#38bdf8; font-weight:700;">✓</span>
                <span>{ev}</span>
            </div>
            """, unsafe_allow_html=True)

        st.markdown(f"""
        <div class="box-title" style="margin-top:20px;">
            {tooltip("🔒", "Zero Trust 대응", "침해 의심 단말 및 타깃 자산에 대한 단계별 자동화 방어 조치 내역입니다.")} Zero Trust 대응 조치 및 격리 상태
        </div>
        """, unsafe_allow_html=True)
        st.markdown(f"""
        <div class="zt-action-card">
            <div class="zt-action-badge">1</div>
            <div>
                <b style="color:#38bdf8;">발원지/단말 제어:</b>
                <code style="color:#4ade80; background:#07111e; padding:2px 6px; border-radius:4px; font-size:12px;">{target_inc.actor}</code>
                관련 활성 세션 강제 만료 및 EDR 격리 대기
            </div>
        </div>
        <div class="zt-action-card">
            <div class="zt-action-badge">2</div>
            <div>
                <b style="color:#38bdf8;">타깃 자산 보호:</b>
                <code style="color:#38bdf8; background:#07111e; padding:2px 6px; border-radius:4px; font-size:12px;">{target_inc.target_asset}</code>
                대상 접근 정책 긴급 강화 및 Direct 접근 차단
            </div>
        </div>
        <div class="zt-action-card">
            <div class="zt-action-badge">3</div>
            <div>
                <b style="color:#38bdf8;">포렌식 아티팩트 보존:</b>
                해당 호스트 메모리 덤프 및 Syslog 스냅샷 생성 완료
            </div>
        </div>
        """, unsafe_allow_html=True)


# VIEW 3: AI·IT 거버넌스 (Shadow IT/AI)
# ==========================================
elif menu == "AI·IT 거버넌스":
    st.markdown("<h2>🤖 사내 섀도우 IT 및 생성형 AI 거버넌스 대시보드</h2>", unsafe_allow_html=True)
    with st.expander("⚡ Gemini AI 실시간 미등록 외부 도메인 진단기 (즉시 테스트)", expanded=True):
        st.markdown("""
        <div style="color:#94a3b8; font-size:12.5px; margin-bottom:10px;">
            사내 임직원이 새롭게 접속한 외부 사이트(도메인)를 입력하면, <b>Gemini LLM</b>이 서비스 성격과 <b>데이터 재학습 위험도</b>를 즉시 판별하고 사내 대체 도구를 추천합니다.
        </div>
        """, unsafe_allow_html=True)
        col_in, col_btn = st.columns([3.5, 1.2])
        with col_in:
            test_domain_input = st.text_input("분석할 도메인 주소", value="perplexity.ai", placeholder="예: perplexity.ai, v0.dev, gamma.app, midjourney.com", label_visibility="collapsed")
        with col_btn:
            btn_run_gemini = st.button("🚀 AI 즉시 진단", use_container_width=True)

        if btn_run_gemini and test_domain_input:
            import os
            active_key = st.session_state.get("gemini_api_key") or os.environ.get("GEMINI_API_KEY")
            with st.spinner(f"'{test_domain_input}' 도메인의 보안 위험도를 Gemini AI로 진단 중..."):
                new_asset = ctx.governance_engine.analyze_and_register_domain(test_domain_input, api_key=active_key)
            st.success(f"'{new_asset.domain}' ({new_asset.service_name}) 분석 완료! [위험도: {new_asset.risk_level.value}] 사내 대체 권고: {new_asset.recommended_alternative}")
            st.rerun()

    shadow_assets = ctx.governance_engine.get_all_assets()

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
# ==========================================
# VIEW 4: 중앙 서버 파이프 라인
# ==========================================
elif menu == "중앙 서버 파이프 라인":
    from nexusguard.collectors.team_collector import (
        fetch_railway_events, fetch_activity_log_events, load_team_guide_markdown, RAILWAY_URL, RAILWAY_API_KEY
    )

    st.markdown(f"""
    <div style="display:flex; align-items:center; gap:8px; margin-bottom: 12px;">
        <h2 style="margin:0; font-size:24px; font-weight:700;">📡 중앙 서버 파이프 라인</h2>
        {tooltip("ℹ️", "중앙 서버 파이프 라인 연동 가이드", "팀원들이 개발한 Windows Agent(NexusGuardAgent.exe)와 Railway 클라우드 중앙 서버(Flask + PostgreSQL)의 실시간 수집 현황 및 연동 가이드입니다.")}
    </div>
    """, unsafe_allow_html=True)

    # Railway 수집 활성화 여부
    from nexusguard.collectors.team_collector import set_railway_collection_enabled, is_railway_collection_enabled
    if "railway_collection_active" not in st.session_state:
        st.session_state["railway_collection_active"] = False
    if "sb_railway_toggle" not in st.session_state:
        st.session_state["sb_railway_toggle"] = st.session_state["railway_collection_active"]
    if "view_railway_collection_toggle" not in st.session_state:
        st.session_state["view_railway_collection_toggle"] = st.session_state["railway_collection_active"]

    def _on_view_railway_toggle():
        val = st.session_state.get("view_railway_collection_toggle", False)
        st.session_state["railway_collection_active"] = val
        st.session_state["sb_railway_toggle"] = val
        set_railway_collection_enabled(val)

    railway_active = st.session_state.get("railway_collection_active", False)

    # 상단 수집 상태 안내 배너 (전체 너비 박스로 복원)
    if railway_active:
        st.markdown("""
        <div style="background: rgba(16, 185, 129, 0.1); border: 1px solid #10b981; border-radius: 10px; padding: 14px 18px; display: flex; align-items: center; margin-bottom: 12px;">
            <span style="font-size: 24px; margin-right: 14px;">🟢</span>
            <div>
                <b style="color: #34d399; font-size: 14px;">Railway 실시간 로그 수집 활성화 (ON)</b><br>
                <span style="color: #cbd5e1; font-size: 12px;">중앙 서버(bountiful-nature-production-22ec.up.railway.app/events)로부터 PC 에이전트 로그를 실시간 수집 중입니다.</span>
            </div>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div style="background: rgba(100, 116, 139, 0.15); border: 1px solid #64748b; border-radius: 10px; padding: 14px 18px; display: flex; align-items: center; margin-bottom: 12px;">
            <span style="font-size: 24px; margin-right: 14px;">⏸️</span>
            <div>
                <b style="color: #94a3b8; font-size: 14px;">Railway 실시간 로그 수집 일시 정지 (OFF)</b><br>
                <span style="color: #cbd5e1; font-size: 12px;">네트워크 API 질의가 중지되었습니다. 하단 스위치를 켜면 즉시 실시간 수집이 재개됩니다.</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

    # 하단으로 분리된 전용 수집 제어 바
    with st.container(border=True):
        col_ctrl1, col_ctrl2 = st.columns([3.2, 1.2])
        with col_ctrl1:
            st.toggle(
                "⚡ Railway 실시간 수집 ON / OFF 스위치", 
                value=st.session_state.get("railway_collection_active", False),
                key="view_railway_collection_toggle", 
                on_change=_on_view_railway_toggle, 
                help="클릭하여 Railway 실시간 로그 수집을 켜거나 끕니다."
            )
        with col_ctrl2:
            if st.button("🔄 최신 로그 즉시 동기화", disabled=not railway_active, use_container_width=True, key="btn_view_sync_now", help="Railway 중앙 서버에서 최신 에이전트 수집 로그를 즉시 갱신합니다."):
                from nexusguard.collectors.team_collector import fetch_railway_events
                r_logs = fetch_railway_events(timeout=5, force=True)
                st.toast(f"🔄 Railway 중앙 서버에서 최신 {len(r_logs)}개 에이전트 로그를 동기화했습니다.", icon="🌐")
                st.rerun()

    st.markdown("<div style='height:8px;'></div>", unsafe_allow_html=True)

    r_events = fetch_railway_events(timeout=5)
    act_events = fetch_activity_log_events()

    # 상단 실시간 메트릭 카드 4종 (높이 및 규격 100% 동일 통일)
    kpi_c1, kpi_c2, kpi_c3, kpi_c4 = st.columns(4)
    with kpi_c1:
        if railway_active:
            server_status_val = "🟢 수집 중 (ON)"
            server_status_color = "#10b981"
        else:
            server_status_val = "⏸️ 수집 정지 (OFF)"
            server_status_color = "#94a3b8"

        st.markdown(f"""
        <div class="kpi-card" style="border-left: 4px solid {server_status_color}; text-align: center; display: flex; flex-direction: column; justify-content: center; align-items: center;">
            <div class="kpi-title" style="text-align: center; width: 100%; margin-bottom: 8px;">Railway 서버 통신 상태</div>
            <div class="kpi-value" style="color:{server_status_color}; font-size:20px; text-align: center; width: 100%;">{server_status_val}</div>
        </div>
        """, unsafe_allow_html=True)
    with kpi_c2:
        st.markdown(f"""
        <div class="kpi-card" style="border-left: 4px solid #38bdf8; text-align: center; display: flex; flex-direction: column; justify-content: center; align-items: center;">
            <div class="kpi-title" style="text-align: center; width: 100%; margin-bottom: 8px;">수집된 실제 에이전트 로그</div>
            <div class="kpi-value" style="color:#38bdf8; font-size:26px; text-align: center; width: 100%;">{len(r_events)} 건</div>
        </div>
        """, unsafe_allow_html=True)
    with kpi_c3:
        st.markdown(f"""
        <div class="kpi-card" style="border-left: 4px solid #a855f7; text-align: center; display: flex; flex-direction: column; justify-content: center; align-items: center;">
            <div class="kpi-title" style="text-align: center; width: 100%; margin-bottom: 8px;">실시간 수집 PC</div>
            <div class="kpi-value" style="color:#a855f7; font-size:17px; text-align: center; width: 100%; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">DESKTOP-OF0CMDB</div>
        </div>
        """, unsafe_allow_html=True)
    with kpi_c4:
        key_status_color = "#10b981" if RAILWAY_API_KEY else "#ef4444"
        key_status_text = "● VERIFIED" if RAILWAY_API_KEY else "○ NOT SET"
        st.markdown(f"""
        <div class="kpi-card" style="border-left: 4px solid {key_status_color}; text-align: center; display: flex; flex-direction: column; justify-content: center; align-items: center;">
            <div class="kpi-title" style="text-align: center; width: 100%; margin-bottom: 8px;">API Key 보안 인증</div>
            <div class="kpi-value" style="color:{key_status_color}; font-size:18px; font-weight:800; text-align: center; width: 100%;">{key_status_text}</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # 탭 구성: [실시간 수집 로그 테이블], [파이프라인 아키텍처], [팀원 가이드 원문]
    tab_logs, tab_arch, tab_guide = st.tabs([
        f"📋 Railway 실시간 수집 로그 ({len(r_events)}건)",
        "🏗️ 4단계 데이터 파이프라인 구조",
        "📖 팀원 공유 초간단 가이드 원문"
    ])

    with tab_logs:
        st.markdown("### 🌐 Railway 중앙 서버 수집 이벤트 (/events)")
        st.caption("각 PC에서 `NexusGuardAgent.exe`가 사이트 접속(DNS)을 자동 감지하여 중앙 서버에 전송한 실제 데이터입니다.")

        col_btn_ref, _ = st.columns([1.5, 4])
        with col_btn_ref:
            if st.button("🔄 Railway 실제 로그 새로고침", use_container_width=True):
                st.rerun()

        if r_events:
            df_rly = pd.DataFrame(r_events)
            cols_order = [c for c in ["id", "event_time", "user_name", "pc_name", "event_type", "target", "source", "risk_score"] if c in df_rly.columns]
            df_display = df_rly[cols_order].rename(columns={
                "id": "ID",
                "event_time": "발생 시각",
                "user_name": "사용자",
                "pc_name": "PC 이름",
                "event_type": "이벤트 종류",
                "target": "접속 사이트",
                "source": "수집 소스",
                "risk_score": "위험 점수"
            })
            st.dataframe(df_display, hide_index=True, use_container_width=True, height=350)
        else:
            st.warning("Railway 서버에서 수집된 로그가 없습니다.")

        st.markdown("---")
        st.markdown("### 💾 사내 DB 감사 활동 로그 (activity.log)")
        st.caption("사내 DB(company_db)의 민감 테이블(`customer_vault`, `customer_db`) 조회 활동 원천 로그입니다.")
        if act_events:
            df_act = pd.DataFrame(act_events).rename(columns={
                "id": "ID",
                "event_time": "발생 시각",
                "user_name": "사용자",
                "pc_name": "PC 이름",
                "event_type": "수행 액션",
                "target": "대상 테이블/도메인",
                "rows": "조회 행 수"
            })
            st.dataframe(df_act, hide_index=True, use_container_width=True)

    with tab_arch:
        st.markdown("### 🔄 NexusGuard 전체 수집 파이프라인 흐름도")
        st.markdown(f"""
        <div style="background:#0b1523; border:1px solid #1e3a5f; border-radius:12px; padding:20px; margin-bottom:15px;">
            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px;">
                <div style="background:#132238; border:1px solid #2563eb; border-radius:8px; padding:12px; flex:1; min-width:180px; text-align:center;">
                    <div style="font-size:24px;">💻</div>
                    <div style="font-weight:bold; color:#60a5fa; font-size:14px; margin-top:4px;">1. 사용자 PC</div>
                    <div style="color:#94a3b8; font-size:12px;">NexusGuardAgent.exe</div>
                    <div style="color:#cbd5e1; font-size:11px; margin-top:4px;">크롬/브라우저 사이트 접속 감지</div>
                </div>
                <div style="color:#38bdf8; font-size:20px; font-weight:bold;">➔</div>
                <div style="background:#132238; border:1px solid #10b981; border-radius:8px; padding:12px; flex:1; min-width:180px; text-align:center;">
                    <div style="font-size:24px;">⚡</div>
                    <div style="font-weight:bold; color:#34d399; font-size:14px; margin-top:4px;">2. Railway 중앙 서버</div>
                    <div style="color:#94a3b8; font-size:12px;">Flask /events API</div>
                    <div style="color:#cbd5e1; font-size:11px; margin-top:4px;">인터넷 REST API로 수신</div>
                </div>
                <div style="color:#38bdf8; font-size:20px; font-weight:bold;">➔</div>
                <div style="background:#132238; border:1px solid #a855f7; border-radius:8px; padding:12px; flex:1; min-width:180px; text-align:center;">
                    <div style="font-size:24px;">🗄️</div>
                    <div style="font-weight:bold; color:#c084fc; font-size:14px; margin-top:4px;">3. PostgreSQL DB</div>
                    <div style="color:#94a3b8; font-size:12px;">events 테이블</div>
                    <div style="color:#cbd5e1; font-size:11px; margin-top:4px;">클라우드 데이터 영구 저장</div>
                </div>
                <div style="color:#38bdf8; font-size:20px; font-weight:bold;">➔</div>
                <div style="background:#132238; border:1px solid #f59e0b; border-radius:8px; padding:12px; flex:1; min-width:180px; text-align:center;">
                    <div style="font-size:24px;">🛡️</div>
                    <div style="font-weight:bold; color:#fbbf24; font-size:14px; margin-top:4px;">4. Streamlit UI</div>
                    <div style="color:#94a3b8; font-size:12px;">NexusGuard 대시보드</div>
                    <div style="color:#cbd5e1; font-size:11px; margin-top:4px;">실시간 상관분석 & 관제 화면</div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("#### ⚙️ 실제 연동 코드 규격 (팀원 가이드 4번 항목)")
        st.code(f"""
import os
import requests

url = "{RAILWAY_URL}"
headers = {{
    "X-API-Key": os.getenv("RAILWAY_API_KEY")  # .env 보안 환경변수에서 로드
}}

response = requests.get(url, headers=headers, timeout=5)
response.raise_for_status()
logs = response.json()
        """, language="python")

    with tab_guide:
        guide_text = load_team_guide_markdown()
        st.markdown(guide_text)
