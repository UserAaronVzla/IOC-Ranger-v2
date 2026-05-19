from ioc_ranger_v2.ioc_types import EmailResult


def test_email_result_defaults():
    r = EmailResult(ioc="user@example.com")
    assert r.ioc == "user@example.com"
    assert r.hunter_result is None
    assert r.hunter_score is None
    assert r.disposable is None
    assert r.webmail is None
    assert r.mx_records is None
    assert r.viewdns_reputation is None
    assert r.viewdns_shared_mx is None


def test_email_result_full():
    r = EmailResult(
        ioc="user@example.com",
        hunter_result="deliverable",
        hunter_score=90,
        disposable=False,
        webmail=True,
        mx_records=True,
        viewdns_reputation="Good",
        viewdns_shared_mx=5,
    )
    assert r.hunter_result == "deliverable"
    assert r.hunter_score == 90
    assert r.disposable is False
    assert r.webmail is True
    assert r.viewdns_shared_mx == 5


def test_email_result_dict_roundtrip():
    r = EmailResult(ioc="x@y.com", hunter_result="risky", hunter_score=30)
    d = r.__dict__
    r2 = EmailResult(**d)
    assert r2.ioc == "x@y.com"
    assert r2.hunter_result == "risky"
    assert r2.hunter_score == 30
