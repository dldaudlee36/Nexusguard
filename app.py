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

# Execute in Streamlit's script namespace so timed fragments keep the same
# script identity across navigation and automatic reruns.
dashboard_file = root_dir / "nexusguard" / "ui" / "app.py"
__file__ = str(dashboard_file)
exec(compile(dashboard_file.read_text(encoding="utf-8"), str(dashboard_file), "exec"), globals())
