# SPDX-License-Identifier: Apache-2.0
"""
CRATB-Auth SDK (`dc+sd-jwt`)
Extension URI: https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1
"""

EXTENSION_URI = "https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1"

from .models import (
    AIAgentIdentityCredential,
    IdentityChallenge,
    IdentityResponse,
    TunneledChallenge,
    TunneledResponse,
    AI_AGENT_IDENTITY_VCT,
    ErrorCode,
    ExtensionSupportRequiredError,
    TaskNotFoundError,
    VersionNotSupportedError,
    A2AProtocolError,
    is_collision_resistant_type,
    DCQLQuery,
    DCQLCredentialQuery,
    DCQLClaimQuery,
    VPFormatsSupported,
    AgentCardExtensionParams,
    OwnerClaim,
    OwnerType,
    KeyProtectionLevel,
    TLS_EXPORTER,
)
from .crypto import (
    generate_ec_p256_keypair,
    export_jwk_from_private_key,
    export_jwk_from_public_key,
    import_private_key_from_jwk,
    import_public_key_from_jwk,
    compute_sha256_base64url,
    encode_tls_exporter,
)
from .wallet import SDJWTWallet, CredentialItem
from .verifier import SDJWTVerifier, VerificationResult, CredentialVerificationError
from .issuer_discovery import IssuerKeyDiscovery
from . import a2a_wire
from .interceptor import (
    A2ATaskMessage,
    A2ATaskStatus,
    A2ATaskStatusResponse,
    ServerAuthRequiredInterceptor,
)
from .tsl import TokenStatusListClient
from .client_interceptor import ClientAuthHandler

from .relay import PendingTunnel, TunnelError, TunnelRelay, TunnelRelayError

__all__ = [
    "PendingTunnel",
    "TunnelError",
    "TunnelRelay",
    "TunnelRelayError",
    "EXTENSION_URI",
    "AIAgentIdentityCredential",
    "IdentityChallenge",
    "IdentityResponse",
    "TunneledChallenge",
    "TunneledResponse",
    "AI_AGENT_IDENTITY_VCT",
    "is_collision_resistant_type",
    "IssuerKeyDiscovery",
    "ErrorCode",
    "ExtensionSupportRequiredError",
    "TaskNotFoundError",
    "VersionNotSupportedError",
    "A2AProtocolError",
    "a2a_wire",
    "DCQLQuery",
    "DCQLCredentialQuery",
    "DCQLClaimQuery",
    "VPFormatsSupported",
    "AgentCardExtensionParams",
    "OwnerClaim",
    "OwnerType",
    "KeyProtectionLevel",
    "generate_ec_p256_keypair",
    "export_jwk_from_private_key",
    "export_jwk_from_public_key",
    "import_private_key_from_jwk",
    "import_public_key_from_jwk",
    "compute_sha256_base64url",
    "encode_tls_exporter",
    "TLS_EXPORTER",
    "SDJWTWallet",
    "CredentialItem",
    "SDJWTVerifier",
    "VerificationResult",
    "CredentialVerificationError",
    "A2ATaskMessage",
    "A2ATaskStatus",
    "A2ATaskStatusResponse",
    "ServerAuthRequiredInterceptor",
    "TokenStatusListClient",
    "ClientAuthHandler",
]
