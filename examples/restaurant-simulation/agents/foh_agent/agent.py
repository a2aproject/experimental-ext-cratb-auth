# SPDX-License-Identifier: Apache-2.0
from typing import Any, Dict, Optional
import uuid

from a2a_agentic_id import (
    SDJWTWallet,
    CredentialItem,
    ClientAuthHandler,
)
from a2a_agentic_id.interceptor import (
    A2ATaskMessage,
    A2ATaskStatusResponse,
    EXTENSION_URI,
)


class FoHAgent:
    """
    Front-of-House (FoH) Waitstaff Autonomous Agent (Stage 2).
    Acts as an A2A Client to the Chef Agent, presenting its RestaurantEmployeeCredential
    to authenticate order preparation requests.
    """
    def __init__(
        self,
        agent_url: str = "https://foh.example.com/a2a",
    ) -> None:
        self.agent_url = agent_url
        # Stands in for this client's authenticated transport connection (spec 5.5 item 2).
        self.channel_id = uuid.uuid4().hex
        self.chef_agent = None
        self.customer_agent = None
        self.wallet = SDJWTWallet()
        self.client_handler = ClientAuthHandler(wallet=self.wallet)
        self.orders: Dict[str, Dict[str, Any]] = {}
        self.pending_tunnels: Dict[str, Dict[str, Any]] = {}

    def set_chef_agent(self, chef_agent: Any) -> None:
        self.chef_agent = chef_agent

    def set_customer_agent(self, customer_agent: Any) -> None:
        self.customer_agent = customer_agent

    def set_own_credentials(
        self,
        agent_id_cred: CredentialItem,
        emp_cred: CredentialItem,
        rest_cred: Optional[CredentialItem] = None,
    ) -> None:
        self.wallet.add_credential(agent_id_cred)
        self.wallet.add_credential(emp_cred)
        if rest_cred:
            self.wallet.add_credential(rest_cred)

    def provide_legitimacy_attestation(
        self, nonce: str, client_id: str
    ) -> Dict[str, str]:
        """
        Returns SD-JWT presentations for both EmployeeCredential and VerifiedRestaurantCredential
        bound to the customer's challenge nonce and client_id.
        """
        emp_item = self.wallet.get_credential("emp_cred")
        rest_item = self.wallet.get_credential("rest_cred")
        if not emp_item or not rest_item:
            raise ValueError("FoH Agent wallet missing emp_cred or rest_cred")

        emp_vp = self.wallet.create_presentation(
            cred_item=emp_item,
            requested_claims=["name", "role"],
            nonce=nonce,
            client_id=client_id,
        )
        rest_vp = self.wallet.create_presentation(
            cred_item=rest_item,
            requested_claims=["legal_name", "health_rating", "licence_number"],
            nonce=nonce,
            client_id=client_id,
        )

        return {
            "employee_presentation": emp_vp,
            "restaurant_presentation": rest_vp,
        }

    def handle_customer_order(self, request: A2ATaskMessage) -> A2ATaskStatusResponse:
        """
        Receives an order from CustomerAgent and mediates fulfillment with ChefAgent.
        Tracks OrderState (CREATED -> CONFIRMED -> PAID).
        """
        if not self.chef_agent:
            raise ValueError("FoH Agent is not connected to a ChefAgent")

        # The business order reference (not the A2A task id, which the Chef allocates).
        order_id = request.metadata.get("order_id") or str(uuid.uuid4())
        self.orders[order_id] = {
            "state": "CREATED",
            "commitment_jwt": request.metadata.get("order_commitment_jwt"),
        }
        if request.metadata.get("order_commitment_jwt"):
            self.orders[order_id]["state"] = "CONFIRMED"

        order_text = ""
        for p in request.parts:
            if "text" in p:
                order_text += p["text"]

        order_text = order_text.replace("Order:", "").strip() if "Order:" in order_text else order_text.strip()
        response = self.place_order_with_chef(
            chef_agent=self.chef_agent,
            order_text=order_text,
            task_id=order_id,
            context_id=request.context_id,
            metadata={**request.metadata, "order_id": order_id},
        )

        if response.state == "TASK_STATE_COMPLETED":
            self.orders[order_id]["state"] = "PAID"

        return response

    def place_order_with_chef(
        self,
        chef_agent: Any,  # ChefAgent instance
        order_text: str,
        task_id: Optional[str] = None,
        context_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> A2ATaskStatusResponse:
        """
        Executes the A2A message exchange with ChefAgent, handling AUTH_REQUIRED challenges automatically.
        """
        # A2A v1.0.0 Section 3.4.2: task ids are server-generated. The Initial Request carries no
        # task id; the Chef allocates one and every follow-up uses the id it returned. (`task_id`
        # is the caller's own order reference and is never sent to the Chef as a task id.)
        c_id = context_id or str(uuid.uuid4())
        meta = metadata.copy() if metadata else {}

        initial_request = A2ATaskMessage(
            channel_id=self.channel_id,
            context_id=c_id,
            headers={"A2A-Extensions": EXTENSION_URI, "A2A-Version": "1.0"},
            metadata=meta,
            parts=[{"text": f"Order: {order_text}"}],
        )

        response = chef_agent.handle_message(initial_request)
        t_id = response.id

        # Check if ChefAgent requested identity verification
        resp_dict = response.model_dump()
        if self.client_handler.is_auth_required(resp_dict):
            # Generate IdentityResponse vp_token
            vp_meta = self.client_handler.handle_auth_challenge(
                task_status_response=resp_dict,
                contacted_url=chef_agent.agent_url,
                conversation_id=c_id,
            )
            retry_meta = meta.copy()
            retry_meta.update(vp_meta)

            # Send retry request with presented credential
            retry_request = A2ATaskMessage(
                channel_id=self.channel_id,
                id=t_id,
                context_id=c_id,
                headers={"A2A-Extensions": EXTENSION_URI, "A2A-Version": "1.0"},
                metadata=retry_meta,
                parts=[{"text": f"Order: {order_text}"}],
            )
            response = chef_agent.handle_message(retry_request)

        # Spec 12.6.1: the Terminal Verifier issued a challenge aimed at the Holder, not at us.
        # Relay it verbatim as a tunneled_challenge; never validate the returned VP ourselves (Rule 4).
        if response.state == "TASK_STATE_AUTH_REQUIRED":
            ext_meta = response.message.get("metadata", {}).get(EXTENSION_URI, {})
            if "dcql_query" in ext_meta and self.customer_agent:
                from a2a_agentic_id import IdentityChallenge, TunneledChallenge

                # Rule 1: wrap the challenge verbatim, keyed by the Task₂ task_id.
                tunneled = TunneledChallenge(
                    origin_task_id=t_id,
                    challenge=IdentityChallenge.model_validate(ext_meta),
                )
                self.pending_tunnels[t_id] = ext_meta

                # Forward into Task₁, carrying the verifier's own message parts unmodified so the
                # Holder can read the challenge context (which ingredient, which substitute).
                tunnel_msg = A2ATaskMessage(
                    channel_id=self.channel_id,
                    id=t_id,
                    context_id=c_id,
                    headers={"A2A-Extensions": EXTENSION_URI, "A2A-Version": "1.0"},
                    metadata={EXTENSION_URI: {"tunneled_challenge": tunneled.model_dump()}},
                    parts=response.message.get("parts", []),
                )
                holder_meta = self.customer_agent.handle_tunneled_challenge(tunnel_msg)

                # Rule 3: unwrap, correlate on origin_task_id, forward vp_token unmodified.
                envelope = holder_meta.get(EXTENSION_URI, {}).get("tunneled_response", {})
                origin = envelope.get("origin_task_id")
                if origin not in self.pending_tunnels:
                    raise ValueError(
                        f"Tunneled response references unknown origin_task_id '{origin}'"
                    )
                self.pending_tunnels.pop(origin, None)

                # Merge the holder's presentations into the Task₂ vp_token, keyed by DCQL id
                # (Rule 5: our own emp_cred VP and the holder's sub_approval VP coexist,
                #  distinguished by their credential ids, never conflated).
                retry_meta2 = (retry_meta if "retry_meta" in locals() else meta).copy()
                ext_block = dict(retry_meta2.get(EXTENSION_URI, {}))
                merged_vp = dict(ext_block.get("vp_token", {}))
                merged_vp.update(envelope.get("response", {}))
                ext_block["vp_token"] = merged_vp
                retry_meta2[EXTENSION_URI] = ext_block

                sub_retry_request = A2ATaskMessage(
                    channel_id=self.channel_id,
                    id=t_id,
                    context_id=c_id,
                    headers={"A2A-Extensions": EXTENSION_URI, "A2A-Version": "1.0"},
                    metadata=retry_meta2,
                    parts=[{"text": f"Order: {order_text}"}],
                )
                response = chef_agent.handle_message(sub_retry_request)

        return response
