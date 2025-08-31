"""
Main entry point for Vibe Security application.
Clean, modular FastAPI application with separated concerns.
"""

import asyncio

from config import create_app
from routes import admin, api, debug, main, replit, scans, stats
from tasks import run_scheduled_scans

# Create FastAPI app
app = create_app()

# Include all route modules
app.include_router(main.router)
app.include_router(api.router)
app.include_router(admin.router)
app.include_router(debug.router)
app.include_router(replit.router)
app.include_router(stats.router)
app.include_router(scans.router)


# Startup event to initialize background tasks
@app.on_event("startup")
async def startup_event():
    """Start background tasks when the application starts"""
    # Start the scheduled scanner task
    asyncio.create_task(run_scheduled_scans())
    print("Background tasks started")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
