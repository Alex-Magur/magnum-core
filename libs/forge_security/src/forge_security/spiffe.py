import logging
import json
import time
from typing import Callable, Optional
import os

class SVIDRotationWatcher:
    def __init__(
        self,
        cert_path,
        key_path,
        ttl_seconds: int,
        on_rotate: Callable,
        svid_id: str,
        operator: str,
    ):
        self.cert_path = cert_path
        self.key_path = key_path
        self.ttl_seconds = ttl_seconds
        self.on_rotate = on_rotate
        self.svid_id = svid_id
        self.operator = operator
        self.rotation_count = 0
        self.last_cert_pem = None

    async def simulate_rotation(self, new_cert_pem: bytes, new_key_pem: bytes):
        self.rotation_count += 1
        self.last_cert_pem = new_cert_pem

        # Write to audit log
        logger = logging.getLogger("forge.audit")
        payload = {
            "schema": "forge.audit.key_event.v1",
            "key_id": self.svid_id,
            "action": "rotate",
            "operator": self.operator,
            "reason": "rotation simulated",
            "ts": time.time(),
        }
        logger.warning(f"AUDIT {json.dumps(payload)}")

        await self.on_rotate(new_cert_pem, new_key_pem)
