# SPDX-License-Identifier: Apache-2.0
"""
x401 Result Artifact helpers for the restaurant demos. Demo-only: not part of the core SDK (spec Appendix C was removed).
"""
import base64
import json
from typing import Any, Dict, List

RESULT_ARTIFACT_TOKEN_TYPE = "urn:x401:params:oauth:token-type:result_artifact"
TOKEN_EXCHANGE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"


def build_result_artifact(vp_token: Dict[str, List[str]]) -> Dict[str, Any]:
    """Wrap vp_token in an x401 Result Artifact."""
    return {
        "credential_result": {
            "protocol": "openid4vp",
            "data": {"vp_token": vp_token},
        }
    }


def encode_result_artifact(artifact: Dict[str, Any]) -> str:
    """Base64url-encode Result Artifact without padding."""
    raw = json.dumps(artifact, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_result_artifact(encoded: str) -> Dict[str, Any]:
    """Decode base64url-encoded Result Artifact."""
    padded = encoded + "=" * (-len(encoded) % 4)
    return json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))


def extract_vp_token(artifact: Dict[str, Any]) -> Dict[str, List[str]]:
    """Extract vp_token mapping from a Result Artifact."""
    result = artifact.get("credential_result")
    if not isinstance(result, dict):
        raise ValueError("Result Artifact is missing the 'credential_result' object")

    protocol = result.get("protocol")
    if protocol != "openid4vp":
        raise ValueError(f"Unsupported Result Artifact protocol: {protocol!r}")

    data = result.get("data")
    if not isinstance(data, dict):
        raise ValueError("Result Artifact is missing 'credential_result.data'")

    vp_token = data.get("vp_token")
    if not isinstance(vp_token, dict):
        raise ValueError("Result Artifact is missing 'credential_result.data.vp_token'")

    return vp_token
