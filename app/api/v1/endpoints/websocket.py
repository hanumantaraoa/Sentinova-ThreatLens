import logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status
from jose import jwt, JWTError
from typing import List, Dict

from app.core.config import settings

logger = logging.getLogger("threatlens.websocket")
router = APIRouter()


class ConnectionManager:
    """Manages active WebSocket browser connections and real-time broadcasts (NFR-02 compliance)."""

    def __init__(self):
        # Maps user session identifiers to their active connection channels
        self.active_connections: Dict[str, WebSocket] = {}

    async def connect(self, websocket: WebSocket, username: str):
        await websocket.accept()
        self.active_connections[username] = websocket
        logger.info(f"WebSocket session established cleanly for user: {username}")

    def disconnect(self, username: str):
        if username in self.active_connections:
            del self.active_connections[username]
            logger.info(f"WebSocket session terminated for user: {username}")

    async def broadcast_event(self, message: dict):
        """Streams event payloads out to all actively connected SOC dashboards simultaneously."""
        disconnected_clients = []
        for username, connection in self.active_connections.items():
            try:
                await connection.send_json(message)
            except Exception:
                # Capture connection breakdowns to clean up resources later
                disconnected_clients.append(username)

        for username in disconnected_clients:
            self.disconnect(username)


# Instantiate a global connection manager instance
manager = ConnectionManager()


@router.websocket("/alerts/stream")
async def alerts_realtime_stream(websocket: WebSocket, token: str):
    """
    Exposes an authenticated WebSocket channel to push live threat alerts
    directly to analyst workspaces (FR-15 Compliance).
    """
    username = "UNKNOWN_CLIENT"
    try:
        # Validate connection tokens securely at the socket handshake layer
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        username = payload.get("sub")
        if username is None:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
    except JWTError:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await manager.connect(websocket, username)

    try:
        # Maintain an open network connection loop to capture incoming client keep-alives
        while True:
            # Operational configuration: Sockets operate in listen/receive mode here
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(username)
    except Exception as exc:
        logger.error(f"WebSocket transmission error encountered: {str(exc)}")
        manager.disconnect(username)
