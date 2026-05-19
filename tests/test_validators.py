from ioc_ranger_v2.validators import classify, is_email


def test_is_email_basic():
    assert is_email("user@example.com") is True
    assert is_email("actor@evil.ru") is True
    assert is_email("first.last+tag@subdomain.org") is True


def test_is_email_rejects_non_emails():
    assert is_email("google.com") is False
    assert is_email("8.8.8.8") is False
    assert is_email("https://example.com") is False
    assert is_email("abc") is False
    assert is_email("") is False


def test_classify_email():
    assert classify("user@example.com") == "email"
    assert classify("malware@phishing.ru") == "email"
    assert classify("name+filter@corp.co.uk") == "email"


def test_classify_email_before_domain():
    assert classify("user@domain.com") != "domain"


def test_classify_others_unchanged():
    assert classify("8.8.8.8") == "ip"
    assert classify("google.com") == "domain"
    assert classify("https://example.com/path") == "url"
    assert classify("a" * 32) == "hash"
