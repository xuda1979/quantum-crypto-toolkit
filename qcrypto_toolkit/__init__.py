"""Post-quantum protocol toolkit prototypes.

The package implements the patent-level protocol mechanics for:

* QCH-KEM: quantum-classical hybrid key encapsulation coordination.
* DLHP: dynamic multi-primitive cryptographic hopping with threshold splitting.

The included cryptographic primitives are demonstration adapters built from the
Python standard library. They are useful for integration tests, protocol traces,
and simulations, but they are not replacements for audited ML-KEM/QKD stacks.
"""

from .dlhp import DLHPSession, ReplayWindow
from .gui import build_dashboard_html, handle_api_request
from .policy import DeploymentProfile, recommend_suite
from .qch_kem import QCHKEM, QKDKeyBuffer, QRNGHealth
from .reports import build_campaign_report, build_profile_matrix, build_profile_sweep, build_security_report, catalog_to_jsonable

__all__ = [
    "__version__",
    "DLHPSession",
    "DeploymentProfile",
    "QCHKEM",
    "QKDKeyBuffer",
    "QRNGHealth",
    "ReplayWindow",
    "build_campaign_report",
    "build_dashboard_html",
    "build_profile_matrix",
    "build_profile_sweep",
    "build_security_report",
    "catalog_to_jsonable",
    "handle_api_request",
    "recommend_suite",
]

__version__ = "0.8.0"
