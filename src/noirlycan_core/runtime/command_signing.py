"""Ed25519-signed console → agent commands.

The backend signs every command it queues; the agent verifies the signature
with a pinned public key, checks the command is addressed to it, not expired,
and not replayed. A network attacker or a tampered database row therefore
cannot make an agent kill processes or run samples.
"""

from __future__ import annotations

import base64
import json
import secrets
import time
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

KEY_FILE = ".command_signing_key"
COMMAND_TTL = timedelta(minutes=10)
ENVELOPE_FIELDS = ("command_id", "agent_id", "issued_at", "expires_at", "nonce")


class CommandRejected(ValueError):
    pass


def _canonical(command: dict[str, Any]) -> bytes:
    unsigned = {key: value for key, value in command.items() if key != "sig"}
    return json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class CommandSigner:
    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._key = private_key

    @classmethod
    def load_or_create(cls, logs_dir: Path) -> CommandSigner:
        path = logs_dir / KEY_FILE
        if path.is_file():
            raw = base64.b64decode(path.read_text(encoding="utf-8").strip())
            return cls(Ed25519PrivateKey.from_private_bytes(raw))
        key = Ed25519PrivateKey.generate()
        raw = key.private_bytes_raw()
        path.write_text(base64.b64encode(raw).decode("ascii"), encoding="utf-8")
        path.chmod(0o600)
        return cls(key)

    @property
    def public_key(self) -> str:
        raw = self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return base64.b64encode(raw).decode("ascii")

    def sign(self, agent_id: str, command: str, params: dict[str, Any], *, command_id: int) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        envelope = {
            **params,
            "command": command,
            "command_id": command_id,
            "agent_id": agent_id,
            "issued_at": now.isoformat(),
            "expires_at": (now + COMMAND_TTL).isoformat(),
            "nonce": secrets.token_hex(16),
        }
        envelope["sig"] = base64.b64encode(self._key.sign(_canonical(envelope))).decode("ascii")
        return envelope


class CommandVerifier:
    def __init__(self, public_key: str, agent_id: str, *, max_nonces: int = 4096) -> None:
        self._key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key))
        self._agent_id = agent_id
        self._seen: OrderedDict[str, float] = OrderedDict()
        self._max_nonces = max_nonces

    def verify(self, command: dict[str, Any]) -> None:
        missing = [field for field in (*ENVELOPE_FIELDS, "sig") if not command.get(field)]
        if missing:
            raise CommandRejected(f"unsigned command (missing {', '.join(missing)})")
        try:
            self._key.verify(base64.b64decode(str(command["sig"])), _canonical(command))
        except (InvalidSignature, ValueError) as exc:
            raise CommandRejected("bad signature") from exc
        if command["agent_id"] != self._agent_id:
            raise CommandRejected("addressed to another agent")
        if datetime.fromisoformat(str(command["expires_at"])) < datetime.now(timezone.utc):
            raise CommandRejected("expired")
        nonce = str(command["nonce"])
        if nonce in self._seen:
            raise CommandRejected("replayed")
        self._seen[nonce] = time.monotonic()
        while len(self._seen) > self._max_nonces:
            self._seen.popitem(last=False)
