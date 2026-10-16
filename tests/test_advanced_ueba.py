import pytest
import json
from app import app
from ueba_engine import (
    analyze_text_sentiment, score_graph_traversal_anomaly,
    verify_behavioral_biometrics, calculate_shannon_entropy, detect_dns_tunneling,
    get_jit_micro_containment_tier, request_dual_auth_unmask, process_event
)

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_nlp_sentiment_velocity():
    # Test high flight risk text
    text = "Management is corrupt, I am quitting and downloading codebase files before leaving."
    res = analyze_text_sentiment(text, previous_score=0.10, delta_t_days=1.0)
    assert res["flight_risk"] is True
    assert res["sentiment_velocity"] > 0.15
    assert len(res["reasons"]) > 0

def test_graph_traversal_anomaly():
    # Rahul (Marketing) accessing db_payroll_core via host_marketing_01
    res = score_graph_traversal_anomaly("u_rahul", "db_payroll_core", "host_marketing_01")
    assert res["is_atypical_traversal"] is True
    assert res["graph_anomaly_score"] >= 70

def test_behavioral_biometrics():
    # High flight time & dwell time deviation > 3.5 sigma
    res = verify_behavioral_biometrics("u_rahul", flight_time_ms=210.0, dwell_time_ms=160.0, mouse_jitter=35.0)
    assert res["mfa_required"] is True
    assert res["sigma_deviation"] > 3.5

def test_shannon_entropy_and_dns_tunneling():
    # High entropy payload (256 unique byte values = 8.0 bits/byte entropy)
    payload = bytes(range(256))
    entropy_score = calculate_shannon_entropy(payload)
    assert entropy_score > 7.5

    # DNS tunneling detection
    dns_res = detect_dns_tunneling("chunk1.exfil.attacker-c2-domain.com")
    assert dns_res["is_dns_tunnel"] is True

def test_jit_micro_containment_tiers():
    assert get_jit_micro_containment_tier(20)["tier"] == "Low"
    assert get_jit_micro_containment_tier(45)["tier"] == "Medium"
    assert get_jit_micro_containment_tier(75)["tier"] == "High"
    assert get_jit_micro_containment_tier(95)["tier"] == "Critical"

def test_zero_trust_unmasking(client):
    # Trigger critical alert
    ev = process_event("u_rahul", 2, 3450.0, "executive_salaries_2026.xlsx", "External USB Drive")
    alert_id = ev["alert_id"]

    # Request unmask with invalid tokens should fail
    unmask_fail = client.post('/api/ueba/unmask', data=json.dumps({
        "alert_id": alert_id,
        "token_lead_1": "SOC_1",
        "token_lead_2": "SOC_1"  # Duplicate token
    }), content_type='application/json')
    assert unmask_fail.status_code == 400

    # Request unmask with valid distinct lead tokens
    unmask_success = client.post('/api/ueba/unmask', data=json.dumps({
        "alert_id": alert_id,
        "token_lead_1": "SOC_LEAD_01",
        "token_lead_2": "HR_DIR_02"
    }), content_type='application/json')
    assert unmask_success.status_code == 200
    data = unmask_success.get_json()
    assert data["status"] == "success"
    assert data["real_name"] == "Rahul Verma"

def test_ip_geolocation_impossible_travel(client):
    res = client.post('/api/ueba/ip_track', data=json.dumps({
        "origin_ip": "108.12.44.1",
        "origin_city": "New York",
        "destination_ip": "82.165.197.1",
        "destination_city": "London",
        "time_delta_mins": 10.0
    }), content_type='application/json')
    assert res.status_code == 200
    data = res.get_json()
    assert data["is_impossible_travel"] is True
    assert data["required_velocity_mph"] > 500.0
    assert data["distance_miles"] > 3000.0
