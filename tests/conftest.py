"""Shared pytest configuration for the Adversum test suite.

Why this file exists
--------------------
``api/main.py`` binds ``API_KEY = os.getenv("API_KEY", "adv-dev-key-123")`` at
*import* time.  pytest imports every test module during collection, before any
test runs.  So a module-level ``os.environ["API_KEY"] = ...`` in one test file
poisons the entire session: modules that re-read ``os.getenv("API_KEY")`` at
import time then send a key that no longer matches the one bound inside
``api.main``, and every authenticated request dies with ``403 Invalid API Key``.

This conftest turns that implicit, order-dependent contract into an explicit
one:

1. A deterministic ``API_KEY`` is exported *before* anything imports
   ``api.main`` (this module is loaded before the test modules in this
   directory, and ``tests/`` is the first entry of ``testpaths``).
2. An autouse fixture snapshots and restores both ``os.environ`` and
   ``api.main.API_KEY`` around *every* test, so no test can leak configuration
   into the next one — whatever the file or directory ordering.

The canonical key is ``adv-dev-key-123``, the project's documented development
default: it is the value already pinned in ``tests/`` headers and in ``.env``,
so enforcing it keeps the existing suite green.  Tests that need a different
key must override it in a module-scoped autouse fixture (see
``api/test_api_local.py``), never at import time.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

#: Deterministic API key for the whole suite. Must match the value hardcoded in
#: the existing ``tests/`` headers and in ``.env``.
TEST_API_KEY = "adv-dev-key-123"

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# --- 1. Deterministic configuration, before any `api.main` import -----------
# Deliberately an assignment (not `setdefault`): neither a developer shell nor
# a stale `.env` may change the key the tests authenticate with.
os.environ["API_KEY"] = TEST_API_KEY


_UNSET = object()


def _api_main_module():
    """Return the already-imported ``api.main`` module, if any.

    Deliberately does **not** import it: this fixture must stay cheap for the
    many tests that never touch the API.
    """
    return sys.modules.get("api.main")


@pytest.fixture(autouse=True)
def isolate_test_config(monkeypatch):
    """Snapshot global config, force canonical values, restore afterwards.

    Protects against the exact defect that broke the suite before: a test
    mutating process-global state (``os.environ`` or ``api.main.API_KEY``)
    and silently changing the behaviour of unrelated tests.
    """
    api_main = _api_main_module()
    saved_environ = dict(os.environ)
    saved_module_key = getattr(api_main, "API_KEY", _UNSET)

    monkeypatch.setenv("API_KEY", TEST_API_KEY)
    if api_main is not None:
        monkeypatch.setattr(api_main, "API_KEY", TEST_API_KEY, raising=False)

    try:
        yield
    finally:
        # `monkeypatch` only undoes *its own* edits, so reconcile anything a
        # test wrote straight into `os.environ` or `api.main.API_KEY` too.
        os.environ.clear()
        os.environ.update(saved_environ)

        if api_main is not None:
            if saved_module_key is _UNSET:
                if hasattr(api_main, "API_KEY"):
                    delattr(api_main, "API_KEY")
            else:
                api_main.API_KEY = saved_module_key
