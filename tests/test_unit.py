import json
import ipaddress
from unittest.mock import patch, mock_open
import pytest
from accessVerifier import update_allowed_ips, is_allowed, allowed_ips, load_allowed_ips

# Example AWS IP ranges data for testing
AWS_IP_RANGES = {
    "syncToken": "1631552573",
    "createDate": "2021-09-13-23-49-33",
    "prefixes": [
        {
            "ip_prefix": "3.5.140.0/22",
            "region": "eu-west-1",
            "service": "AMAZON",
            "network_border_group": "eu-west-1"
        },
        {
            "ip_prefix": "52.95.245.0/24",
            "region": "us-east-1",
            "service": "AMAZON",
            "network_border_group": "us-east-1"
        }
    ],
    "ipv6_prefixes": []
}

@pytest.fixture
def mock_response():
    return json.dumps(AWS_IP_RANGES)

@patch("requests.get")
def test_update_allowed_ips(mock_get, mock_response):
    # Mock the response from requests.get
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = AWS_IP_RANGES

    # Clear the allowed_ips list before testing
    allowed_ips.clear()
    update_allowed_ips()
    assert len(allowed_ips) == 1  # Only one prefix matches eu-west-1
    assert ipaddress.ip_network("3.5.140.0/22") in allowed_ips

def test_is_allowed():
    # Set up allowed_ips for testing is_allowed
    allowed_ips.clear()
    allowed_ips.append(ipaddress.ip_network("3.5.140.0/22"))

    # Test an IP within the allowed range
    assert is_allowed("3.5.140.50") is True
    # Test an IP outside the allowed range
    assert is_allowed("52.95.245.5") is False

@patch("builtins.open", new_callable=mock_open, read_data="3.5.140.0/22\n")
def test_load_allowed_ips(mock_file):
    allowed_ips.clear()
    load_allowed_ips()
    assert len(allowed_ips) == 1
    assert ipaddress.ip_network("3.5.140.0/22") in allowed_ips
