"""
Vercel serverless entrypoint for Autonomous AI SOC Analyst FastAPI app.
"""

from api.app import app

# Vercel WSGI/ASGI handler
app = app
