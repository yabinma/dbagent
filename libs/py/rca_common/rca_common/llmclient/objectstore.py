"""Object store abstraction for evidence/prompt/response payloads
(design.md Section 3.2: "S3-compatible store"). A fake in-memory
implementation is used in unit tests per the Section 14.2 mock matrix.
"""
from __future__ import annotations

from typing import Protocol


class ObjectStore(Protocol):
    def put(self, key: str, data: bytes, content_type: str = "application/json") -> str:
        """Stores `data` under `key`; returns the reference (S3 key) used
        elsewhere as `*_ref` columns."""

    def get(self, key: str) -> bytes:
        """Returns the raw bytes stored under `key`."""

    def presigned_url(self, key: str, expires_seconds: int = 300) -> str:
        """Returns a short-TTL pre-signed download URL."""


class S3ObjectStore:
    """boto3-backed implementation for any S3-compatible endpoint (MinIO
    included)."""

    def __init__(self, client, bucket: str):
        self._client = client
        self._bucket = bucket

    def put(self, key: str, data: bytes, content_type: str = "application/json") -> str:
        self._client.put_object(
            Bucket=self._bucket, Key=key, Body=data, ContentType=content_type
        )
        return key

    def get(self, key: str) -> bytes:
        resp = self._client.get_object(Bucket=self._bucket, Key=key)
        return resp["Body"].read()

    def presigned_url(self, key: str, expires_seconds: int = 300) -> str:
        return self._client.generate_presigned_url(
            "get_object",
            Params={"Bucket": self._bucket, "Key": key},
            ExpiresIn=expires_seconds,
        )


class FakeObjectStore:
    """In-memory `ObjectStore` used by unit tests (Section 14.2: S3 is
    mocked in the unit and functional tiers)."""

    def __init__(self):
        self.objects: dict[str, bytes] = {}

    def put(self, key: str, data: bytes, content_type: str = "application/json") -> str:
        self.objects[key] = data
        return key

    def get(self, key: str) -> bytes:
        return self.objects[key]

    def presigned_url(self, key: str, expires_seconds: int = 300) -> str:
        return f"https://fake-s3.local/{key}?expires={expires_seconds}"
