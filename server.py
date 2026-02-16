import os
import sys

# Keep project directory on sys.path for static serving compatibility
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, send_from_directory
import db as db_module
from flask_socketio import SocketIO

# register chat handlers from chatcontainer
from chatcontainer import register_chat_handlers

app = Flask(__name__, static_folder='static')
import logging

# Reduce noisy low-level socket logging so raw message payloads are not
# printed to the server console. The server still relays messages,
# but engineio/socketio debug output is suppressed for privacy and clarity.
logging.getLogger('engineio').setLevel(logging.WARNING)
logging.getLogger('socketio').setLevel(logging.WARNING)

socketio = SocketIO(
    app,
    cors_allowed_origins='*',
    async_mode='threading',
    logger=False,
    engineio_logger=False,
    # allow larger websocket/polling payloads (50 MB)
    max_http_buffer_size=(50 * 1024 * 1024)
)

# Ensure DB exists
try:
    db_module.init_db()
except Exception:
    app.logger.exception('DB init failed')

# In-memory room membership tracking (no secrets stored)
ROOM_MEMBERS = {}  # room_id -> set(usernames)
SID_MAP = {}       # sid -> (room_id, username)
# Room symmetric keys stored in memory only: room_id -> bytes
ROOM_KEYS = {}

# Register centralized chat handlers
register_chat_handlers(socketio, app, db_module, ROOM_MEMBERS, SID_MAP, ROOM_KEYS)


@app.route('/')
def index():
    return send_from_directory('static', 'client.html')


@app.route('/room/<room_id>')
def room_page(room_id):
    return send_from_directory('static', 'room.html')


@app.route('/docs')
def docs_page():
    return send_from_directory('.', 'QSEC2_Architecture.html')


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host='0.0.0.0', port=port)
