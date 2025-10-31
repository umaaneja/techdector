# tests/test_corpus.py
import pytest
from app.detector import StaticDetector

@pytest.fixture
def detector():
    return StaticDetector()

def test_wordpress_detection(detector):
    # tiny HTML snapshot that should trigger WordPress
    html = "<html><head><meta name='generator' content='WordPress 5.9' /></head><body><script src='/wp-includes/js/jquery.js'></script></body></html>"
    resp = {"text": html, "headers": {"Server":"Apache"}}
    evidence = detector.collect_static(resp)
    res = detector.match(evidence)
    names = [r['name'] for r in res]
    assert "WordPress" in names

def test_nginx_header(detector):
    html = "<html></html>"
    resp = {"text": html, "headers": {"Server":"nginx/1.21"}}
    evidence = detector.collect_static(resp)
    res = detector.match(evidence)
    names = [r['name'] for r in res]
    assert "Nginx" in names
