import os
import io
import json
import pytest
from unittest.mock import MagicMock
from PIL import Image
import app

# Define a mock response structure
class MockGenAIResponse:
    def __init__(self, text_content):
        self.text = text_content

@pytest.fixture
def client():
    app.app.config['TESTING'] = True
    # Ensure app.client is set to a mock object
    app.client = MagicMock()
    with app.app.test_client() as client:
        yield client

def test_home_page(client):
    """Test that the index/home page loads successfully."""
    response = client.get('/')
    assert response.status_code == 200
    assert b"ScamShield" in response.data



def test_analyze_text_success(client):
    """Test successful message scan analysis."""
    # Set mock response for text analysis
    mock_json = '{"risk_score": 90, "verdict": "High Risk Scam", "reasons": ["Urgent request for money", "Suspicious link included"]}'
    app.client.models.generate_content.return_value = MockGenAIResponse(mock_json)

    post_data = {"text": "Congratulations! You won a lottery. Click here to claim: http://fake.com"}
    response = client.post(
        '/analyze-text',
        data=json.dumps(post_data),
        content_type='application/json'
    )
    
    assert response.status_code == 200
    res_json = json.loads(response.data.decode('utf-8'))
    assert res_json['risk_score'] == 90
    assert res_json['verdict'] == "High Risk Scam"
    assert "Urgent request for money" in res_json['reasons']
    
    # Verify the mock was called with correct parameters
    app.client.models.generate_content.assert_called()

def test_analyze_text_empty(client):
    """Test text analysis returns 400 when no text is provided."""
    response = client.post(
        '/analyze-text',
        data=json.dumps({"text": ""}),
        content_type='application/json'
    )
    assert response.status_code == 400
    res_json = json.loads(response.data.decode('utf-8'))
    assert "error" in res_json

def test_analyze_text_api_failure(client):
    """Test text analysis route returns 500 when client raises exception."""
    app.client.models.generate_content.side_effect = Exception("API connection timed out")

    response = client.post(
        '/analyze-text',
        data=json.dumps({"text": "Hello world"}),
        content_type='application/json'
    )
    assert response.status_code == 500
    res_json = json.loads(response.data.decode('utf-8'))
    assert "API connection timed out" in res_json['error']

def test_analyze_url_success(client):
    """Test website link analysis returns valid threat scores."""
    mock_json = '{"risk_score": 15, "verdict": "Safe", "reasons": ["HTTPS enabled", "Known clean domain"]}'
    app.client.models.generate_content.return_value = MockGenAIResponse(mock_json)

    post_data = {"url": "https://paypal.com/signin"}
    response = client.post(
        '/analyze-url',
        data=json.dumps(post_data),
        content_type='application/json'
    )
    
    assert response.status_code == 200
    res_json = json.loads(response.data.decode('utf-8'))
    assert res_json['risk_score'] == 15
    assert res_json['verdict'] == "Safe"

def test_analyze_url_empty(client):
    """Test URL analysis returns 400 when no URL is provided."""
    response = client.post(
        '/analyze-url',
        data=json.dumps({"url": ""}),
        content_type='application/json'
    )
    assert response.status_code == 400

def test_scan_qr_phishing(client):
    """Test QR Code Phishing (Quishing) Scanner route."""
    res = client.post('/api/scan_qr', data=json.dumps({
        "qr_payload": "https://secure-login-verify-account-update.xyz/auth"
    }), content_type='application/json')
    assert res.status_code == 200
    data = res.get_json()
    assert data["is_phishing"] is True
    assert data["risk_score"] == 92

def test_track_scammer_node(client):
    """Test Scammer Node Hop Tracking route."""
    res = client.post('/api/track_scammer', data=json.dumps({
        "target_query": "185.220.101.5"
    }), content_type='application/json')
    assert res.status_code == 200
    data = res.get_json()
    assert data["is_tor_proxy"] is True
    assert len(data["hops"]) == 4

def test_analyze_image_success(client):
    """Test screenshot analysis with simulated multipart file upload."""
    mock_json = '{"extracted_text": "Call this number immediately", "risk_score": 75, "verdict": "Suspicious", "reasons": ["Urgent alert banner"]}'
    app.client.models.generate_content.return_value = MockGenAIResponse(mock_json)

    # Generate a simple red image in memory
    img_byte_arr = io.BytesIO()
    Image.new('RGB', (100, 100), color='red').save(img_byte_arr, format='JPEG')
    img_byte_arr.seek(0)
    
    response = client.post(
        '/analyze-image',
        data={'image': (img_byte_arr, 'test.jpg')},
        content_type='multipart/form-data'
    )
    assert response.status_code == 200
    res_json = json.loads(response.data.decode('utf-8'))
    assert res_json['risk_score'] == 75
    assert res_json['verdict'] == 'Suspicious'
    assert 'extracted_text' in res_json

def test_track_scammer_no_threat(client):
    """Test tracking clean safe scan target yields no scammer IP."""
    post_data = {"verdict": "Safe"}
    response = client.post(
        '/track-scammer',
        data=json.dumps(post_data),
        content_type='application/json'
    )
    assert response.status_code == 200
    res_json = json.loads(response.data.decode('utf-8'))
    assert res_json['status'] == 'no_threat'

def test_sandbox_preset_detonate(client):
    """Test detonation of standard preset sandbox template."""
    post_data = {"payloadType": "ransomware"}
    response = client.post(
        '/sandbox-detonate',
        data=json.dumps(post_data),
        content_type='application/json'
    )
    assert response.status_code == 200
    res_json = json.loads(response.data.decode('utf-8'))
    assert res_json['status'] == 'success'
    assert res_json['score'] == 100

def test_sandbox_custom_detonate_pro(client):
    """Test custom payload detonation success for premium users."""
    post_data = {
        "payloadType": "custom",
        "customPayload": "eval(window.cookie);",
        "isPremium": True
    }
    response = client.post(
        '/sandbox-detonate',
        data=json.dumps(post_data),
        content_type='application/json'
    )
    assert response.status_code == 200
    res_json = json.loads(response.data.decode('utf-8'))
    assert res_json['status'] == 'success'
    assert res_json['score'] > 90

def test_sandbox_custom_detonate_free_blocked(client):
    """Test custom payload detonation is blocked for free users."""
    post_data = {
        "payloadType": "custom",
        "customPayload": "eval(window.cookie);",
        "isPremium": False
    }
    response = client.post(
        '/sandbox-detonate',
        data=json.dumps(post_data),
        content_type='application/json'
    )
    assert response.status_code == 403
    res_json = json.loads(response.data.decode('utf-8'))
    assert 'error' in res_json
    assert 'restricted' in res_json['error']

def test_api_live_feed(client):
    """Test real-time threat feed API."""
    res = client.get('/api/live_feed')
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "success"
    assert len(data["feed"]) > 0

def test_api_demo_samples(client):
    """Test 1-click sample presets API."""
    res = client.get('/api/demo_samples')
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "success"
    assert "text" in data["samples"]
    assert "urls" in data["samples"]

def test_api_generate_report(client):
    """Test executive report generation API."""
    res = client.post('/api/generate_report', data=json.dumps({
        "type": "Cyber Defense Audit Report",
        "data": {"risk": "Low"}
    }), content_type='application/json')
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "success"
    assert "report_id" in data["report"]

def test_chatbot_prank_reply(client):
    """Test chatbot appropriately handles harmless pranks and jokes."""
    # When client is None or offline
    app.client = None
    res = client.post('/chatbot', data=json.dumps({
        "message": "tomorrow's classes will be replaced by a compulsory 3-hour dance competition! And guess what? YOU have been selected as the chief dancer! RELAXXX, IT'S A PRANK! GOT YOU!",
        "lang": "en"
    }), content_type='application/json')
    assert res.status_code == 200
    data = res.get_json()
    assert "Haha" in data["reply"] or "prank" in data["reply"]
    assert "Note:" not in data["reply"]

def test_chatbot_upi_fraud_reply(client):
    """Test chatbot gives accurate safety advice on UPI QR code requests."""
    app.client = None
    res = client.post('/chatbot', data=json.dumps({
        "message": "Buyer says scan this QR code on PhonePe to receive ₹2,000 for my old sofa. Should I scan it?",
        "lang": "en"
    }), content_type='application/json')
    assert res.status_code == 200
    data = res.get_json()
    assert "Never scan a QR code" in data["reply"] or "debit" in data["reply"]

def test_api_share_scan(client):
    """Test share scan backend endpoint produces persistent share URL and messaging links."""
    res = client.post('/api/share_scan', data=json.dumps({
        "elementId": "urlResult",
        "scan_title": "URL Threat Scan",
        "verdict": "Critical Phishing Risk",
        "risk_score": 95,
        "reasons": ["Credential harvesting pattern detected"],
        "target": "https://secure-login-verify-account.xyz"
    }), content_type='application/json')
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "success"
    assert "share_id" in data
    assert "whatsapp_url" in data
    assert "telegram_url" in data

    # Retrieve shared scan
    get_res = client.get(f'/api/share/{data["share_id"]}')
    assert get_res.status_code == 200
    assert get_res.get_json()["data"]["verdict"] == "Critical Phishing Risk"

def test_api_premium_qr_credentials(client):
    """Test premium QR endpoint serves Sachi Nitin Surana's UPI credentials and image."""
    res = client.get('/api/premium_qr')
    assert res.status_code == 200
    data = res.get_json()
    assert data["account_name"] == "Sachi Nitin Surana"
    assert data["upi_id"] == "8263934906@fam"
    assert data["qr_image"] == "/static/images/premium_qr_user.jpg"




