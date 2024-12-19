import json
import ipaddress
import pytest
from unittest.mock import patch
from accessVerifier import app, allowed_ips

AWS_IP_RANGES = {
    "prefixes": [
        {
            "ip_prefix": "3.5.140.0/22",
            "region": "eu-west-1",
            "service": "AMAZON",
            "network_border_group": "eu-west-1"
        }
    ],
    "ipv6_prefixes": []
}

@pytest.fixture
def client():
    # Returns a Flask test client
    with app.test_client() as client:
        yield client

@patch("requests.get")
def test_integration_allowed_ip(mock_get, client):
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = AWS_IP_RANGES

    # Reload allowed IPs
    allowed_ips.clear()
    from accessVerifier import update_allowed_ips
    update_allowed_ips()

    response = client.post("/verify", headers={
        "X-Forwarded-For": "3.5.140.50",
        "X-API-Key": "your_secure_api_key"
    })
    assert response.status_code == 200

@patch("requests.get")
def test_integration_denied_ip(mock_get, client):
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = AWS_IP_RANGES

    allowed_ips.clear()
    from accessVerifier import update_allowed_ips
    update_allowed_ips()

    # Test an IP outside the allowed range
    response = client.post("/verify", headers={
        "X-Forwarded-For": "52.95.245.5",
        "X-API-Key": "your_secure_api_key"
    })
    assert response.status_code == 401

def test_integration_invalid_api_key(client):
    # Test a request with an invalid API key
    response = client.post("/verify", headers={"X-API-Key": "wrong_key"})
    assert response.status_code == 403
