"""
NexusGuard - Root Entry Point for Streamlit Cloud
Streamlit Cloud 기본 실행 파일(app.py) 호환용 엔트리포인트
"""

import sys
from pathlib import Path

# 루트 디렉토리를 Python 모듈 검색 경로에 최우선 등록
root_dir = Path(__file__).resolve().parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

import importlib

# NexusGuard 메인 대시보드 로드 (Streamlit 재실행 시 모듈 리로드 보장)
if "nexusguard.ui.app" in sys.modules:
    importlib.reload(sys.modules["nexusguard.ui.app"])
else:
    import nexusguard.ui.app
