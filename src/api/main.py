"""FastAPI application entry point for the Agent Sandbox Escape Detector."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.api.routes import router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> None:  # noqa: ARG001
    """Application lifespan handler for startup/shutdown events.

    Args:
        app: The FastAPI application instance.
    """
    logger.info("Agent Sandbox Escape Detector API starting up...")
    yield
    logger.info("Agent Sandbox Escape Detector API shutting down...")


app = FastAPI(
    title="Agent Sandbox Escape Detector",
    description="Black-box test LLM agent systems for sandbox escape vulnerabilities.",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS middleware for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)