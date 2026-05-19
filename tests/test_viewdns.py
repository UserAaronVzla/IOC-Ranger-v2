import asyncio
from unittest.mock import AsyncMock, MagicMock


def _make_client_with_responses(responses: list[dict]) -> AsyncMock:
    mock_client = AsyncMock()
    mock_responses = []
    for body in responses:
        r = MagicMock()
        r.json.return_value = body
        r.raise_for_status = MagicMock()
        mock_responses.append(r)
    mock_client.get.side_effect = mock_responses
    return mock_client


def test_check_email_reputation_and_shared_mx():
    async def _run():
        from ioc_ranger_v2.services.viewdns import check_email
        client = _make_client_with_responses([
            {"response": {"result": "Good"}},
            {"response": {"mx": [{"priority": "10", "name": "mail.example.com"}]}},
            {"response": {"domains": [{"name": "a.com"}, {"name": "b.com"}, {"name": "c.com"}, {"name": "d.com"}]}},
        ])
        result = await check_email(client, "fake_key", "user@example.com")
        assert result["viewdns_reputation"] == "Good"
        assert result["viewdns_shared_mx"] == 4

    asyncio.run(_run())


def test_check_email_no_mx_records():
    async def _run():
        from ioc_ranger_v2.services.viewdns import check_email
        client = _make_client_with_responses([
            {"response": {"result": "Bad"}},
            {"response": {"mx": []}},
        ])
        result = await check_email(client, "fake_key", "user@nodomain.xyz")
        assert result["viewdns_reputation"] == "Bad"
        assert result["viewdns_shared_mx"] is None

    asyncio.run(_run())


def test_check_email_reputation_failure_still_returns_mx():
    async def _run():
        import httpx
        from ioc_ranger_v2.services.viewdns import check_email

        client = AsyncMock()
        bad_response = MagicMock()
        bad_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "404", request=MagicMock(), response=MagicMock()
        )
        bad_response.json.return_value = {}
        mx_response = MagicMock()
        mx_response.raise_for_status = MagicMock()
        mx_response.json.return_value = {"response": {"mx": [{"priority": "10", "name": "mail.x.com"}]}}
        rev_response = MagicMock()
        rev_response.raise_for_status = MagicMock()
        rev_response.json.return_value = {"response": {"domains": [{"name": "other.com"}]}}
        client.get.side_effect = [bad_response, mx_response, rev_response]

        result = await check_email(client, "fake_key", "user@x.com")
        assert result["viewdns_reputation"] is None
        assert result["viewdns_shared_mx"] == 1

    asyncio.run(_run())
