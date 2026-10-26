# SPDX-License-Identifier: Apache-2.0
import os
import sys

import pytest

# Make the demo-domain package (`restaurant_domain`) importable from tests.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Modules that test the A2A v1.0.0 task-id rule itself and so must see the real behaviour.
_REAL_TASK_ID_RULE = ("test_a2a_v1",)


@pytest.fixture(autouse=True)
def _tests_choose_their_own_task_ids(request, monkeypatch):
    """
    A2A v1.0.0 Section 3.4.2: task ids are server-generated, and a client-provided `taskId` MUST
    reference an existing task or the agent returns TaskNotFoundError. The interceptor enforces
    that. Most tests exercise something else (nonces, sessions, DCQL ...) and name their own
    task ids for readability, so for them every id counts as already allocated, the same way they
    already seed `active_nonces` and `authenticated_tasks` directly. The rule itself is tested,
    unpatched, in `tests/conformance/test_a2a_v1.py`.
    """
    if request.module.__name__.rsplit(".", 1)[-1] in _REAL_TASK_ID_RULE:
        return
    from a2a_agentic_id.interceptor import ServerAuthRequiredInterceptor

    monkeypatch.setattr(ServerAuthRequiredInterceptor, "_is_known_task", lambda self, task_id: True)
