import pytest
import json
from app import app
from ueba_engine import process_event, USERS, RESOURCE_SENSITIVITY, ALERT_FEED, ueba_instance

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_isolation_forest_and_watchlist():
    # Rahul Verma (on watchlist) accessing executive salaries off-hours
    ev = process_event("u_rahul", 2, 2450.0, "executive_salaries_2026.xlsx", "External USB Drive")
    assert ev["risk_score"] >= 80
    assert ev["severity"] in ["Critical", "High"]
    assert any("WATCHLIST AMPLIFIER" in r for r in ev["reasons"])

def test_canary_honeypot_trap():
    # Canary honeypot file trigger
    ev = process_event("u_ananya", 14, 10.0, "canary_honeypot_passwords.xlsx", "External USB Drive")
    assert ev["risk_score"] >= 70
    assert any("HONEYPOT TRAP TRIGGERED" in r for r in ev["reasons"])

def test_peer_group_suppression():
    # Vikram Patel (DevOps) performing normal work hours transfer
    ev = process_event("u_vikram", 14, 1100.0, "engineering_codebase.tar.gz", "Dev Server Build")
    # Should trigger peer group suppression and remain low/medium risk
    assert ev["risk_score"] < 60
    assert any("PEER GROUP SUPPRESSION" in r for r in ev["reasons"])

def test_flask_api_simulate(client):
    res = client.post('/api/simulate', data=json.dumps({
        "user_id": "u_rahul",
        "hour": 2,
        "transfer_mb": 2500,
        "file_accessed": "executive_salaries_2026.xlsx",
        "destination": "External USB Drive"
    }), content_type='application/json')
    
    assert res.status_code == 200
    data = res.get_json()
    assert data["risk_score"] >= 80
    assert "reasons" in data

def test_flask_api_ueba_dashboard(client):
    res = client.get('/api/ueba/dashboard')
    assert res.status_code == 200
    data = res.get_json()
    assert data["total_entities_monitored"] >= 4

def test_post_user_entity(client):
    payload = {
        "name": "Priya Sharma",
        "department": "Engineering",
        "role": "Lead Security Engineer",
        "baseline_avg_mb": 150,
        "baseline_std_mb": 45,
        "start_hour": 9,
        "end_hour": 18,
        "on_watchlist": False
    }
    res = client.post('/api/ueba/user', data=json.dumps(payload), content_type='application/json')
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "success"
    assert "Priya Sharma" in data["message"]

    dash_res = client.get('/api/ueba/dashboard')
    dash_data = dash_res.get_json()
    assert any(u["name"] == "Priya Sharma" for u in dash_data["users"])
