# SPDX-License-Identifier: Apache-2.0
"""Prepends the `a2a_agentic_id` SDK (`sdk/python`) to `sys.path`.

Every module in this package (bootstrap_keys, identity, a2a_caller, the three
agent.py files, and run_adk.py itself) imports `a2a_agentic_id` at module
scope. This runs first, on any `import common` or `import common.<module>`,
so none of those imports need their own path shim.

This reads the SDK straight from its source tree if not already installed
via `pip install -e sdk/python`.
"""

import sys
from pathlib import Path

_SDK_ROOT = Path(__file__).resolve().parents[3] / "sdk" / "python"
if str(_SDK_ROOT) not in sys.path:
    sys.path.insert(0, str(_SDK_ROOT))

# Demo-domain credentials (order, substitution) live with the restaurant-simulation example.
_DOMAIN_ROOT = Path(__file__).resolve().parents[2] / "restaurant-simulation"
if str(_DOMAIN_ROOT) not in sys.path:
    sys.path.insert(0, str(_DOMAIN_ROOT))
