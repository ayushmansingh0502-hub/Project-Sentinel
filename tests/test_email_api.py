import pytest
from httpx import ASGITransport, AsyncClient

from main import app


@pytest.mark.asyncio
async def test_analyze_email_returns_forensic_response(monkeypatch):
    monkeypatch.setenv("API_KEY", "test-api-key")
    payload = {
        "from_email": "alerts@paypa1.xyz",
        "from_name": "Bank Support",
        "message_text": "Your account is blocked. Verify now.",
        "raw_headers": "From: Bank Support <alerts@paypa1.xyz>\nAuthentication-Results: mx; spf=fail; dkim=fail; dmarc=fail\nReceived: from 8.8.8.8 by mx.example; Thu, 12 Sep 2026 10:00:00 +0000",
    }

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/analyze-email", headers={"x-api-key": "test-api-key"}, json=payload)

    assert response.status_code == 200
    body = response.json()
    assert body["header_analysis"]["authentication"]["spf"] == "fail"
    assert body["brand_spoof"]["suspected"] is True