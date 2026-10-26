**Title: Full-Cycle Voucher Redemption with Verifiable Consent**

A demonstration of a complete lifecycle of a food order, from initial customer request to final
preparation, with mandatory **non-repudiable verifiability** built into every decision point.

> Assumption: all actors had obtained their respective verifiable credentials already


## Actors
| Actor | Role  | Descrption |
| :--- | :--- | :--- |
| **Human** | The User | Initiates the process and provides final, verifiable consent. |
| **Customer Agent** | The Customer Gateway | Captures user intent, manages the interaction flow, and handles the generation/submission of signed Verifiable Presentations. |
| **FoH Agent** | Front-of-House Agent | Verifies credentials, acts as the central coordinator, and mediates communications between the customer and the kitchen. |
| **Chef Agent** | Fulfillment Executor | Translates intent into actionable tasks, interacts with backend APIs, and manages process changes. |
| **Kitchen API** | The Resource Backend | Enforces access control and manages physical resources (inventory, preparation). |

## Flow

| Stage | Key Action | Actors Involved | What's under the hood |
| :--- | :--- | :--- | :--- |
| **0. Voucher Issuance** | The Human already holds a Voucher (a JWT, issuer-signed) and uploads it to the Customer Agent's ADK-WEB interface. | Issuer ➔ Human | This is just a JSON/JWT file that the User uploads via the customer_agent ADK-WEB. |
| **1. Initiation** | The Customer Agent parses the uploaded Voucher JWT into a redemption intent (e.g., "Grilled Cheese"). It initiates the request through the Front-of-House (FoH) Agent. | Human ➔ Customer Agent ➔ FoH Agent | **Role-Based Start:** The FoH Agent verifies identity credentials (Restaurant/Employee) and validates the Voucher's signature/claims. |
| **2. Execution & Conflict** | The FoH Agent routes the order to the Chef Agent. The Chef Agent attempts to fulfill the order by calling backend APIs (Kitchen API). A resource constraint (e.g., "No gluten-free bread") is detected. | FoH ➔ Chef Agent ➔ Kitchen API | **Access Control:** API calls enforce granular permissions. **Lack of ingredient Detection:** Resource failure triggers an unavailable error. |
| **3. Negotiation** | The Chef Agent proposes a solution (e.g., substitution) to the FoH Agent. The FoH Agent relays this proposal to the Customer Agent for review. | Chef ➔ FoH ➔ Customer Agent | **Re-planning:** Failure requires mandatory mediation. |
| **4. Verifiable Agreement** | The human reviews the proposed change and provides explicit, signed consent. The Customer Agent transforms this decision into a cryptographically signed **Verifiable Presentation (VP)**. | Human ➔ Customer Agent | **Non-Repudiation:** The signed VP locks in the agreement, proving consent was given by the customer. |
| **5. Completion** | The FoH Agent validates the signed agreement and passes the updated order to the Chef Agent. The Chef Agent uses the modified parameters to successfully complete the order via the Kitchen API. | FoH ➔ Chef Agent ➔ Kitchen API | **Finalization:** Trust is established, and the successful, modified transaction completes the lifecycle. |