#!/usr/bin/env python3
# Web-Based Real-Time Chat - Server
# This module serves the HTML chat interface and handles WebSocket connections for real-time messaging.

import asyncio
import websockets
import http.server
import socketserver
import threading
import json
import os
import logging
from urllib.parse import urlparse, parse_qs

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('WebChat')

# Global variables
connected_clients = set()
HTTP_PORT = 8000
WS_PORT = 8001

class ChatHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    """Handler for serving static HTML and associated files"""
    
    def __init__(self, *args, **kwargs):
        # Set the directory to the location of this script
        directory = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
        super().__init__(*args, directory=directory, **kwargs)
    
    def log_message(self, format, *args):
        """Override to use our logger instead of stdout"""
        logger.info("%s - %s" % (self.address_string(), format % args))

    def do_GET(self):
        """Handle GET requests"""
        # Parse the URL path
        parsed_url = urlparse(self.path)
        path = parsed_url.path
        
        # Serve the chat.html file for the root path
        if path == "/":
            self.path = "/chat.html"
            
        return http.server.SimpleHTTPRequestHandler.do_GET(self)

async def handler(websocket):
    """Handle WebSocket connections"""
    # Client connected
    client_info = f"{websocket.remote_address[0]}:{websocket.remote_address[1]}"
    logger.info(f"Client connected: {client_info}")
    
    # Add to the set of connected clients
    connected_clients.add(websocket)
    
    try:
        # Send welcome message to the new client
        await websocket.send(json.dumps({
            "type": "system",
            "message": "Welcome to the chat! There are currently " + 
                      f"{len(connected_clients)} user(s) online."
        }))
        
        # Notify all other clients about the new user
        if len(connected_clients) > 1:
            await notify_all_except(websocket, {
                "type": "system",
                "message": f"A new user has joined the chat. " +
                          f"There are now {len(connected_clients)} users online."
            })
        
        # Keep the connection open and receive messages
        async for message in websocket:
            try:
                # Parse the message as JSON
                data = json.loads(message)
                username = data.get("username", "Anonymous")
                text = data.get("message", "")
                
                if text.strip():  # Only process non-empty messages
                    logger.info(f"Message from {username}: {text}")
                    
                    # Broadcast the message to all clients
                    await broadcast({
                        "type": "chat",
                        "username": username,
                        "message": text
                    })
            
            except json.JSONDecodeError:
                logger.warning(f"Received invalid JSON from {client_info}: {message}")
                # Send error message back to the client
                await websocket.send(json.dumps({
                    "type": "error",
                    "message": "Invalid message format"
                }))
    
    except websockets.exceptions.ConnectionClosed:
        logger.info(f"Connection closed for {client_info}")
    
    finally:
        # Remove from the set of connected clients
        connected_clients.remove(websocket)
        
        # Notify remaining clients about the user leaving
        if connected_clients:
            await broadcast({
                "type": "system",
                "message": f"A user has left the chat. There are now {len(connected_clients)} user(s) online."
            })

async def broadcast(message):
    """Broadcast a message to all connected clients"""
    if connected_clients:  # Check if there are any connected clients
        json_message = json.dumps(message)
        await asyncio.gather(
            *[client.send(json_message) for client in connected_clients]
        )

async def notify_all_except(exclude_websocket, message):
    """Send a message to all clients except the excluded one"""
    if len(connected_clients) > 1:  # Only if there are other clients
        json_message = json.dumps(message)
        await asyncio.gather(
            *[client.send(json_message) for client in connected_clients if client != exclude_websocket]
        )

def start_http_server():
    """Start the HTTP server in a separate thread"""
    handler = ChatHTTPRequestHandler
    server = socketserver.ThreadingTCPServer(("", HTTP_PORT), handler)
    logger.info(f"HTTP server started on port {HTTP_PORT}")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()

async def start_websocket_server():
    """Start the WebSocket server"""
    async with websockets.serve(handler, "", WS_PORT):
        logger.info(f"WebSocket server started on port {WS_PORT}")
        await asyncio.Future()  # Run forever

def main():
    """Main function to start both servers"""
    # Create the web directory if it doesn't exist
    web_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
    if not os.path.exists(web_dir):
        os.makedirs(web_dir)
    
    # Start HTTP server in a separate thread
    http_thread = threading.Thread(target=start_http_server, daemon=True)
    http_thread.start()
    
    # Start WebSocket server in the main thread
    try:
        asyncio.run(start_websocket_server())
    except KeyboardInterrupt:
        logger.info("Server shutdown requested")
    
    logger.info("Chat server stopped")

if __name__ == "__main__":
    main()