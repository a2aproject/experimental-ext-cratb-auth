# SPDX-License-Identifier: Apache-2.0
"""Process-startup compat shim: a2a-sdk 1.1.2 vs. the installed protobuf's upb backend.

a2a.utils.proto_utils imports FieldDescriptor from google.protobuf.descriptor (the
pure-Python class) and reads its deprecated public `.label` attribute. At runtime,
though, real descriptors are instances of the C-accelerated
google._upb._message.FieldDescriptor -- an unrelated class (not a subclass of the
pure-Python one) that never defined `.label` publicly, only the `is_repeated`
property. That mismatch makes every A2A request fail with
`AttributeError: ... FieldDescriptor' object has no attribute 'label'`
(see https://github.com/a2aproject/a2a-python/issues/1011).

This must run BEFORE a2a-sdk (or anything that imports it) is loaded: a2a-sdk's
own request-validation code (jsonrpc_dispatcher.py) runs on every incoming A2A
request as soon as the server process wires up its routes, which happens before
ADK's AgentLoader ever imports an app's agent.py. Importing this module from
agent.py is therefore too late for the SERVER side of an A2A call -- it must be
imported at process startup, before `adk web` itself is invoked. See run_adk.py.
"""

from google._upb._message import FieldDescriptor as _UpbFieldDescriptor

if not hasattr(_UpbFieldDescriptor, "label"):
    from google.protobuf.descriptor import FieldDescriptor as _PyFieldDescriptor

    def _label(self: object) -> int:
        return (
            _PyFieldDescriptor.LABEL_REPEATED
            if self.is_repeated  # type: ignore[attr-defined]
            else _PyFieldDescriptor.LABEL_OPTIONAL
        )

    _UpbFieldDescriptor.label = property(_label)
