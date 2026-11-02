"""Read-only Control Center read-model API.

A standalone, stdlib-only HTTP service that serves versioned, bounded JSON
views for the control-center surfaces (Command Deck, Work Board, Squad,
Signal, Governance, Delivery). Every view is built from existing
``arvyx_control`` projections over a vault and a control-event log; the
service has no mutation routes and never writes to either.
"""

from arvyx_control import __version__

API_VERSION = "v1"
SCHEMA = "arvyx-control-center/v1"
SERVICE = "arvyx-control-center-api"

__all__ = ["API_VERSION", "SCHEMA", "SERVICE", "__version__"]
