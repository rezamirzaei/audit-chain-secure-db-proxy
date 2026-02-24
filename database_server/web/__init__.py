"""HTML web routes for database_server."""

from .auth_routes import DatabaseAuthRoutes
from .page_routes import DatabasePageRoutes
from .routes import DatabaseWebRoutes

__all__ = ["DatabaseAuthRoutes", "DatabasePageRoutes", "DatabaseWebRoutes"]
