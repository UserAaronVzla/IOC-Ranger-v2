import asyncio
from unittest.mock import AsyncMock, MagicMock


def _make_mock_client(json_body: dict) -> AsyncMock:
    mock_response = MagicMock()
    mock_response.json.return_value = json_body
    mock_response.raise_for_status = MagicMock()
    mock_client = AsyncMock()
    mock_client.get.return_value = mock_response
    return mock_client


def test_verify_email_deliverable():
    async def _run():
        from ioc_ranger_v2.services.hunter import verify_email
        client = _make_mock_client({
            "data": {
                "result": "deliverable",
                "score": 92,
                "disposable": False,
                "webmail": False,
                "mx_records": True,
            }
        })
        result = await verify_email(client, "fake_key", "user@corp.com")
        assert result["hunter_result"] == "deliverable"
        assert result["hunter_score"] == 92
        assert result["disposable"] is False
        assert result["webmail"] is False
        assert result["mx_records"] is True

    asyncio.run(_run())


def test_verify_email_disposable():
    async def _run():
        from ioc_ranger_v2.services.hunter import verify_email
        client = _make_mock_client({
            "data": {
                "result": "risky",
                "score": 20,
                "disposable": True,
                "webmail": True,
                "mx_records": True,
            }
        })
        result = await verify_email(client, "fake_key", "temp@mailinator.com")
        assert result["disposable"] is True
        assert result["hunter_result"] == "risky"

    asyncio.run(_run())


def test_verify_email_missing_data_fields():
    async def _run():
        from ioc_ranger_v2.services.hunter import verify_email
        client = _make_mock_client({"data": {}})
        result = await verify_email(client, "fake_key", "x@y.com")
        assert result["hunter_result"] is None
        assert result["hunter_score"] is None
        assert result["disposable"] is None

    asyncio.run(_run())
