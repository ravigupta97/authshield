"""
Root conftest.py — applies to the entire test session.
Sets the Windows-compatible event loop policy BEFORE any
test infrastructure is initialized.
"""
import asyncio
import os
import sys
import pytest

# Set TESTING=true BEFORE any app code is imported.
# This disables rate limiting in check_rate_limit().
os.environ["TESTING"] = "true"

if sys.platform == "win32":
    # WindowsSelectorEventLoopPolicy is compatible with pytest-asyncio.
    # The default ProactorEventLoop on Windows has issues with Redis
    # async connections closing after each test's loop is torn down.
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())