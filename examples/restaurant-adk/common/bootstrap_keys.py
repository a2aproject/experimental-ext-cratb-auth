# SPDX-License-Identifier: Apache-2.0
"""Generate cryptographic key pairs and initial credentials.

Generates EC P-256 keys for issuers and agents.
Issues employee credentials and initial customer voucher.
"""

from a2a_agentic_id import SDJWTWallet, generate_ec_p256_keypair
from a2a_agentic_id.crypto import export_jwk_from_private_key, export_jwk_from_public_key

from common.identity import (
    CHEF_AGENT,
    CHEF_ROLE,
    CUSTOMER_AGENT,
    EMPLOYEE_CREDENTIAL_TYPE,
    FOH_AGENT,
    FOH_ROLE,
    RESTAURANT_ISSUER,
    VOUCHER_CREDENTIAL_TYPE,
    VOUCHER_DIETARY_CLAIM,
    VOUCHER_ENTITLEMENT_CLAIM,
    VOUCHER_ID,
    VOUCHER_ISSUER,
    EMPLOYEE_ROLE_CLAIM,
    save_employee_credential,
    save_private_jwk,
    save_public_jwk,
    save_voucher,
)

VOUCHER_ENTITLEMENT = "Grilled Cheese"
VOUCHER_DIETARY = "gluten-free"


def _generate_and_save_keypair(actor: str) -> tuple[dict, dict]:
    private_key, public_key = generate_ec_p256_keypair()
    private_jwk = export_jwk_from_private_key(private_key)
    public_jwk = export_jwk_from_public_key(public_key)
    save_private_jwk(actor, private_jwk)
    save_public_jwk(actor, public_jwk)
    return private_jwk, public_jwk


def _issue_employee_credential(
    issuer_private_jwk: dict, actor: str, holder_public_jwk: dict, role: str
) -> None:
    sd_jwt_string = SDJWTWallet.issue_sd_jwt(
        issuer_private_key_jwk=issuer_private_jwk,
        iss=RESTAURANT_ISSUER,
        vct=EMPLOYEE_CREDENTIAL_TYPE,
        id_claim=f"emp-{actor}",
        plaintext_claims={},
        sd_claims={EMPLOYEE_ROLE_CLAIM: role},
        holder_public_key_jwk=holder_public_jwk,
    )
    save_employee_credential(actor, sd_jwt_string)


def _issue_voucher(issuer_private_jwk: dict, holder_public_jwk: dict) -> None:
    sd_jwt_string = SDJWTWallet.issue_sd_jwt(
        issuer_private_key_jwk=issuer_private_jwk,
        iss=VOUCHER_ISSUER,
        vct=VOUCHER_CREDENTIAL_TYPE,
        id_claim=VOUCHER_ID,
        plaintext_claims={},
        sd_claims={
            VOUCHER_ENTITLEMENT_CLAIM: VOUCHER_ENTITLEMENT,
            VOUCHER_DIETARY_CLAIM: VOUCHER_DIETARY,
        },
        holder_public_key_jwk=holder_public_jwk,
    )
    voucher_path = save_voucher(sd_jwt_string)
    print(f"Voucher written to {voucher_path}")


def main() -> None:
    voucher_issuer_private_jwk, _ = _generate_and_save_keypair(VOUCHER_ISSUER)
    restaurant_issuer_private_jwk, _ = _generate_and_save_keypair(RESTAURANT_ISSUER)

    _, customer_public_jwk = _generate_and_save_keypair(CUSTOMER_AGENT)
    _, foh_public_jwk = _generate_and_save_keypair(FOH_AGENT)
    _, chef_public_jwk = _generate_and_save_keypair(CHEF_AGENT)

    _issue_employee_credential(restaurant_issuer_private_jwk, FOH_AGENT, foh_public_jwk, FOH_ROLE)
    _issue_employee_credential(restaurant_issuer_private_jwk, CHEF_AGENT, chef_public_jwk, CHEF_ROLE)

    _issue_voucher(voucher_issuer_private_jwk, customer_public_jwk)

    print("Bootstrap complete: keys/ and vouchers/ are ready.")


if __name__ == "__main__":
    main()
