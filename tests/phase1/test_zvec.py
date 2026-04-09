"""Tests for the ZVec client integration."""

import pytest
import httpx
from forge_retrieval.zvec import ZVecClient

pytestmark = pytest.mark.phase1

class MockResponse:
    def __init__(self, json_data, status_code=200):
        self._json_data = json_data
        self.status_code = status_code

    def json(self):
        return self._json_data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("Error", request=None, response=self)

class MockAsyncClient(httpx.AsyncClient):
    async def post(self, url, json, **kwargs):
        if "search" in url:
            return MockResponse({"results": [{"id": "doc1", "score": 0.99}]})
        elif "insert" in url:
            return MockResponse({"status": "success"})
        return MockResponse({}, status_code=404)

    async def aclose(self):
        pass

@pytest.mark.asyncio
async def test_zvec_search():
    client = ZVecClient("http://localhost:8000", http_client=MockAsyncClient())
    results = await client.search("test_col", [0.1, 0.2, 0.3])
    assert len(results) == 1
    assert results[0]["id"] == "doc1"
    await client.close()

@pytest.mark.asyncio
async def test_zvec_insert():
    client = ZVecClient("http://localhost:8000", http_client=MockAsyncClient())
    success = await client.insert("test_col", [0.1, 0.2, 0.3], {"key": "value"}, "doc1")
    assert success is True
    await client.close()
