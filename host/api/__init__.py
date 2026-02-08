from .control import router as control_router
from .dashboard import router as dashboard_router
from .vault import router as vault_router

__all__ = ["control_router", "dashboard_router", "vault_router"]
