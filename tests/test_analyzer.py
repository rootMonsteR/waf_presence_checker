from waf_presence_checker.models import HttpObservation
from waf_presence_checker.analyzer import analyze

def test_basic_detection():
    ob = HttpObservation(
        url="https://example.com",
        method="GET",
        status_code=200,
        headers={
            "server": "cloudflare",
            "cf-ray": "123",
            "set-cookie": "__cfduid=foo"
        }
    )
    rep = analyze(ob)
    assert rep.likely_waf
    assert rep.confidence >= 0.6
