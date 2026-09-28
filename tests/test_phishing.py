import os, sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.detector import PhishingDetector

def test_legitimate_url():
    detector = PhishingDetector()
    res = detector.analyze_url("https://www.google.com")
    assert res["is_phishing"] is False
    assert res["risk_score"] < 40

def test_phishing_url():
    detector = PhishingDetector()
    res = detector.analyze_url("http://192.168.1.1-paypal-login.security-verify.xyz/account")
    assert res["is_phishing"] is True
    assert res["risk_score"] >= 60
    assert "CRITICAL" in res["status"]
