"""Shared fixtures for sync and async client tests."""

import pytest
import respx

from uniplex.client import UniplexClient
from uniplex.async_client import AsyncUniplexClient

BASE_URL = "https://uniplex.ai"
API_KEY = "uni_test_xxx"


@pytest.fixture
def client():
    c = UniplexClient(api_key=API_KEY, base_url=BASE_URL)
    yield c
    c.close()


@pytest.fixture
async def async_client():
    c = AsyncUniplexClient(api_key=API_KEY, base_url=BASE_URL)
    yield c
    await c.close()


@pytest.fixture
def mock_api():
    with respx.mock(base_url=BASE_URL) as router:
        yield router
