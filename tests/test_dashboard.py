from streamlit.testing.v1 import AppTest

from aegisflow.settings import ROOT
from aegisflow.storage import Store


def button(app, label):
    return next(b for b in app.button if b.label == label)


def text(app, label):
    return next(t for t in app.text_input if t.label == label)


def test_dashboard_full_approval_workflow(tmp_path, monkeypatch):
    db_path = str(tmp_path / "ui.db")
    monkeypatch.setenv("AEGIS_DB_PATH", db_path)
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=20).run()
    assert not app.exception
    button(app, "Investigate incident").click().run()
    assert not app.exception
    case = Store(db_path).list()[0]
    assert case.status == "review_required"
    text(app, "Analyst name").set_value("Hannan")
    app.text_area[0].set_value("Verified the synthetic campaign")
    button(app, "Approve simulated containment").click().run()
    assert any("approval box" in e.value for e in app.error)
    assert not Store(db_path).effects(case.id)
    app.checkbox[0].check()
    button(app, "Approve simulated containment").click().run()
    assert not app.exception
    assert Store(db_path).get(case.id).status == "contained"
    assert len(Store(db_path).effects(case.id)) == 5
    assert any("Decision recorded" in row.value for row in app.success)
