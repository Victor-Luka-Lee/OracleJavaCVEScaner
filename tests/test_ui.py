from pathlib import Path

from streamlit.testing.v1 import AppTest


def test_streamlit_dashboard_initial_view_loads():
    app = AppTest.from_file(Path(__file__).parents[1] / "jvi" / "ui.py")
    app.run(timeout=10)
    assert not app.exception
    assert app.title[0].value == "🛡️ Java Vulnerability Inspector"
    assert "검증된 취약점 데이터" in [item.value for item in app.subheader]
