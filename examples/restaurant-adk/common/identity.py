# SPDX-License-Identifier: Apache-2.0
"""Key and credential storage for the 3-agent voucher redemption system.

Manages EC P-256 keys, EmployeeCredentials, and RestaurantVouchers.
"""

import json
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from a2a_agentic_id import CredentialItem, SDJWTWallet
from a2a_agentic_id.crypto import base64url_decode

PROJECT_ROOT = Path(__file__).resolve().parent.parent
KEYS_DIR = PROJECT_ROOT / "keys"
VOUCHERS_DIR = PROJECT_ROOT / "vouchers"

VOUCHER_ISSUER = "voucher_issuer"
RESTAURANT_ISSUER = "restaurant_issuer"
CUSTOMER_AGENT = "customer_agent"
FOH_AGENT = "foh_agent"
CHEF_AGENT = "chef_agent"

# The agent that calls each agent. Log messages use it to name the peer.
CALLER_OF = {FOH_AGENT: CUSTOMER_AGENT, CHEF_AGENT: FOH_AGENT}

VOUCHER_CREDENTIAL_ID = "voucher"
EMPLOYEE_CREDENTIAL_ID = "emp_cred"
SUBSTITUTION_APPROVAL_CREDENTIAL_ID = "sub_approval"

VOUCHER_CREDENTIAL_TYPE = "https://example.com/credentials/RestaurantVoucher/v1"
EMPLOYEE_CREDENTIAL_TYPE = "https://example.com/credentials/EmployeeCredential/v1"
SUBSTITUTION_APPROVAL_CREDENTIAL_TYPE = "https://example.com/credentials/IngredientSubstitutionApproval/v1"

VOUCHER_ENTITLEMENT_CLAIM = "entitlement"
VOUCHER_DIETARY_CLAIM = "dietary"
EMPLOYEE_ROLE_CLAIM = "role"

FOH_ROLE = "foh"
CHEF_ROLE = "chef"

VOUCHER_FILENAME = "grilled-cheese.jwt"
VOUCHER_ID = "grilled-cheese-voucher"


def _private_key_path(actor: str) -> Path:
    return KEYS_DIR / f"{actor}.private.jwk.json"


def _public_key_path(actor: str) -> Path:
    return KEYS_DIR / f"{actor}.public.jwk.json"


def _employee_credential_path(actor: str) -> Path:
    return KEYS_DIR / f"{actor}.emp_cred.sdjwt"


def _read(path: Path, desc: str) -> str:
    if not path.exists():
        raise FileNotFoundError(
            f"Missing {desc}; run `python -m common.bootstrap_keys` first"
        )
    return path.read_text(encoding="utf-8")


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def save_private_jwk(actor: str, jwk: Dict[str, Any]) -> None:
    _write(_private_key_path(actor), json.dumps(jwk))


def save_public_jwk(actor: str, jwk: Dict[str, Any]) -> None:
    _write(_public_key_path(actor), json.dumps(jwk))


def load_private_jwk(actor: str) -> Dict[str, Any]:
    return json.loads(_read(_private_key_path(actor), f"private key for '{actor}'"))


def load_public_jwk(actor: str) -> Dict[str, Any]:
    return json.loads(_read(_public_key_path(actor), f"public key for '{actor}'"))


def trusted_keys(*issuers: str) -> Callable[[str], Dict[str, Any]]:
    """Return a jwks_resolver that knows the public keys of the given issuers only."""
    return lambda iss: load_public_jwk(iss) if iss in issuers else {}


def save_employee_credential(actor: str, sd_jwt_string: str) -> None:
    _write(_employee_credential_path(actor), sd_jwt_string)


def load_employee_credential(actor: str) -> str:
    return _read(_employee_credential_path(actor), f"employee credential for '{actor}'")


def save_voucher(sd_jwt_string: str) -> Path:
    return _write(VOUCHERS_DIR / VOUCHER_FILENAME, sd_jwt_string)


def holder_credential(cred_id: str, sd_jwt_string: str, holder: str) -> CredentialItem:
    """Return a wallet entry bound to the private key of the holder."""
    return CredentialItem(
        id=cred_id, sd_jwt_string=sd_jwt_string, holder_private_key_jwk=load_private_jwk(holder)
    )


def build_employee_wallet(actor: str) -> SDJWTWallet:
    """Wallet for a staff agent (foh_agent/chef_agent): its own holder key plus its EmployeeCredential."""
    wallet = SDJWTWallet()
    wallet.add_credential(
        holder_credential(EMPLOYEE_CREDENTIAL_ID, load_employee_credential(actor), actor)
    )
    return wallet


def build_customer_wallet(voucher: Optional[str] = None) -> SDJWTWallet:
    """Wallet for the customer: its own holder key plus the uploaded voucher, if given."""
    wallet = SDJWTWallet()
    if voucher:
        wallet.add_credential(holder_credential(VOUCHER_CREDENTIAL_ID, voucher, CUSTOMER_AGENT))
    return wallet


def extract_unverified_disclosures(sd_jwt_string: str) -> Dict[str, Any]:
    """Extract claims from SD-JWT disclosures without cryptographic validation."""
    parts = sd_jwt_string.split("~")
    claims: Dict[str, Any] = {}
    for disc_b64 in parts[1:-1]:
        if not disc_b64:
            continue
        try:
            disc_json = json.loads(base64url_decode(disc_b64).decode("utf-8"))
            if len(disc_json) >= 3:
                claims[disc_json[1]] = disc_json[2]
        except Exception:
            continue
    return claims

