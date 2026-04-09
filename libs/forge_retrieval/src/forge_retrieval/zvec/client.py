"""ZVec foundational integration for semantic storage.

This module provides the asynchronous micro-pipeline client for ZVec,
adhering to Phase 2 OpenSandbox security constraints.
"""

from typing import Any, Dict, List, Optional
import httpx
import logging

logger = logging.getLogger(__name__)

class ZVecClient:
    """Asynchronous client for ZVec semantic storage.

    Ensures that vector operations are performed asynchronously
    and respect security boundaries (e.g. using configured secure transports).
    """

    def __init__(self, endpoint_url: str, http_client: Optional[httpx.AsyncClient] = None):
        """Initialize the ZVec client.

        Args:
            endpoint_url: The base URL for the ZVec service.
            http_client: Optional HTTP client to use (for injecting secure transports
                         such as mTLS or proxies enforcing OPA policies).
        """
        self.endpoint_url = endpoint_url.rstrip("/")
        self._client = http_client or httpx.AsyncClient()
        self._owns_client = http_client is None

    async def close(self) -> None:
        """Close the underlying HTTP client if owned by this instance."""
        if self._owns_client:
            await self._client.aclose()

    async def search(self, collection_name: str, query_vector: List[float], limit: int = 10) -> List[Dict[str, Any]]:
        """Perform a semantic search against the ZVec storage.

        Args:
            collection_name: The name of the collection to search.
            query_vector: The vector to search for.
            limit: Maximum number of results to return.

        Returns:
            A list of dictionary results containing the document and score.
        """
        url = f"{self.endpoint_url}/collections/{collection_name}/search"
        payload = {
            "vector": query_vector,
            "limit": limit
        }

        try:
            response = await self._client.post(url, json=payload)
            response.raise_for_status()
            data = response.json()
            return data.get("results", [])
        except httpx.HTTPError as e:
            logger.error(f"ZVec search failed: {e}")
            raise

    async def insert(self, collection_name: str, vector: List[float], payload: Dict[str, Any], doc_id: str) -> bool:
        """Insert a vector and its metadata into the ZVec storage.

        Args:
            collection_name: The target collection name.
            vector: The embedding vector.
            payload: Associated metadata.
            doc_id: Unique identifier for the document.

        Returns:
            True if successful, False otherwise.
        """
        url = f"{self.endpoint_url}/collections/{collection_name}/insert"
        data = {
            "id": doc_id,
            "vector": vector,
            "payload": payload
        }

        try:
            response = await self._client.post(url, json=data)
            response.raise_for_status()
            return True
        except httpx.HTTPError as e:
            logger.error(f"ZVec insert failed: {e}")
            raise
