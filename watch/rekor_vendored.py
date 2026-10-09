"""Vendored, frozen Rekor anchoring for confidior-watch.

This is a deliberately frozen copy of the anchoring path in
``confidior-engine/src/export/rekor.py`` plus the ephemeral-cert helper from
``src/export/dsse.py``. It is **not** imported from the engine, and the engine
is not a dependency of this repo.

Why frozen rather than shared:

- The watch repo's whole value is an unbroken history. A dependency that can
  break the run is worse than a duplicate that cannot.
- The clock cannot be coupled to anything that moves. The engine is a versioned
  product; this crawler must keep running while the engine changes underneath.
- Anchoring is small and stable (~150 lines, unchanged upstream API).

Provenance: copied 2026-10-09 from confidior-engine (Apache-2.0) at the commit in
``VENDORED_FROM``. If you change anchoring upstream, decide deliberately whether
this copy should move with it. Divergence is expected and acceptable; silent
divergence is not, which is why this note is here.

Rekor stores only the hash of what you submit. Nothing observed by this crawler
is ever revealed to the transparency log.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import urllib.error
import urllib.request
from datetime import timedelta
from typing import Any, cast

from watch.clock import utc_now

logger = logging.getLogger(__name__)

VENDORED_FROM = "confidior-engine/src/export/rekor.py + dsse.py (Apache-2.0), 2026-10-09"

SIGNING_CONFIG_URL = (
    "https://raw.githubusercontent.com/sigstore/root-signing/main/"
    "targets/signing_config.v0.2.json"
)

MAX_ATTESTATION_SIZE = 100_000
DEFAULT_GET_TIMEOUT = 10.0
DEFAULT_POST_TIMEOUT = 15.0


class RekorError(Exception):
    """Raised on any Rekor interaction failure (network, parsing, size)."""


def _http_get_json(url: str, timeout: float = DEFAULT_GET_TIMEOUT) -> dict[str, Any]:
    req = urllib.request.Request(url, headers={"User-Agent": "confidior-watch/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return cast(dict[str, Any], json.loads(resp.read().decode("utf-8")))


def _http_post_json(url: str, body: bytes, timeout: float = DEFAULT_POST_TIMEOUT) -> dict[str, Any]:
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "confidior-watch/0.1"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return cast(dict[str, Any], json.loads(resp.read().decode("utf-8")))


def get_rekor_url(*, fetcher: Any = None, timeout: float = DEFAULT_GET_TIMEOUT) -> str:
    """Fetch the currently-active Rekor log URL from the TUF SigningConfig."""
    if fetcher is None:

        def _default_fetcher(url: str) -> dict[str, Any]:
            return _http_get_json(url, timeout=timeout)

        fetcher = _default_fetcher
    try:
        config = fetcher(SIGNING_CONFIG_URL)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as e:
        raise RekorError(f"Failed to fetch Rekor SigningConfig: {e}") from e
    except json.JSONDecodeError as e:
        raise RekorError(f"Rekor SigningConfig is not valid JSON: {e}") from e

    urls = config.get("rekorTlogUrls", [])
    if not urls:
        raise RekorError("Rekor SigningConfig contains no rekorTlogUrls")
    return cast(str, urls[0]["url"])


def build_hashedrekord_entry(
    payload: bytes,
    signature: bytes,
    public_key: bytes,
    hash_algorithm: str = "sha256",
) -> dict[str, Any]:
    """Build a Rekor v1 hashedrekord entry. Stores the payload hash, never the payload."""
    h = hashlib.new(hash_algorithm, payload)
    return {
        "kind": "hashedrekord",
        "apiVersion": "0.0.1",
        "spec": {
            "data": {"hash": {"algorithm": hash_algorithm, "value": h.hexdigest()}},
            "signature": {
                "content": base64.b64encode(signature).decode("ascii"),
                "publicKey": {"content": base64.b64encode(public_key).decode("ascii")},
            },
        },
    }


def submit_entry(
    entry: dict[str, Any],
    rekor_url: str,
    *,
    poster: Any = None,
    timeout: float = DEFAULT_POST_TIMEOUT,
) -> dict[str, Any]:
    """Submit a built Rekor entry. Returns the log entry including uuid and logIndex."""
    body = json.dumps(entry).encode("utf-8")
    if len(body) > MAX_ATTESTATION_SIZE:
        raise RekorError(
            f"Entry size {len(body)} bytes exceeds Rekor public instance limit "
            f"({MAX_ATTESTATION_SIZE} bytes)"
        )

    if poster is None:

        def _default_poster(url: str, body: bytes) -> dict[str, Any]:
            return _http_post_json(url, body, timeout=timeout)

        poster = _default_poster

    url = rekor_url.rstrip("/") + "/api/v1/log/entries"
    try:
        result = cast(dict[str, Any], poster(url, body))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as e:
        raise RekorError(f"Rekor submission failed: {e}") from e
    except json.JSONDecodeError as e:
        raise RekorError(f"Rekor response is not valid JSON: {e}") from e

    uuid = next(iter(result))
    log_entry: dict[str, Any] = result[uuid]
    log_entry["uuid"] = uuid
    return log_entry


def _make_ephemeral_ecdsa_cert() -> tuple[Any, bytes]:
    """Generate an ephemeral ECDSA P-256 keypair and self-signed cert.

    Rekor v1 hashedrekord does not support Ed25519, so an ephemeral ECDSA key is
    used purely for submission and discarded immediately. It is unrelated to any
    other key this project holds (the project holds none).
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    ecdsa_key = ec.generate_private_key(ec.SECP256R1())
    pub = ecdsa_key.public_key()
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "confidior-watch-rekor")]
    )
    now = utc_now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(pub)
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .sign(ecdsa_key, hashes.SHA256())
    )
    return ecdsa_key, cert.public_bytes(serialization.Encoding.PEM)


def anchor_digest(
    digest: str,
    *,
    poster: Any = None,
    url_fetcher: Any = None,
    rekor_url: str | None = None,
) -> dict[str, Any]:
    """Anchor a hex digest to Sigstore Rekor. Returns a result dict.

    Anchors the digest string itself; Rekor stores only its hash. Raises
    :class:`RekorError` on failure -- callers decide whether that is fatal.
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils

    ecdsa_key, cert_pem = _make_ephemeral_ecdsa_cert()
    payload = digest.encode("ascii")
    sig = ecdsa_key.sign(
        hashlib.sha256(payload).digest(),
        ec.ECDSA(utils.Prehashed(hashes.SHA256())),
    )
    entry = build_hashedrekord_entry(payload, sig, cert_pem)
    if rekor_url is None:
        rekor_url = get_rekor_url(fetcher=url_fetcher)
    result = submit_entry(entry, rekor_url, poster=poster)
    # The url is returned with the entry so a caller can record where the proof
    # landed. Without it the anchor is submitted and then unfindable: the uuid
    # alone does not say which transparency log holds it.
    return {
        "log_index": result.get("logIndex"),
        "uuid": result.get("uuid", ""),
        "rekor_url": rekor_url,
    }
