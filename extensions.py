from flask_socketio import SocketIO
from authlib.integrations.flask_client import OAuth
from flask_babel import Babel

socketio = SocketIO(cors_allowed_origins="*")
oauth = OAuth()
babel = Babel()
