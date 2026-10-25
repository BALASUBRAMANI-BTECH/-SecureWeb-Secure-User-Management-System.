import os
from app import create_app
from app.extensions import db

env = os.environ.get("FLASK_ENV", "development")
app = create_app(env)

if __name__ == "__main__":
    # Ensure tables are created for local development
    with app.app_context():
        db.create_all()

    # Default to localhost:5000
    host = os.environ.get("FLASK_RUN_HOST", "127.0.0.1")
    port = int(os.environ.get("FLASK_RUN_PORT", 5000))
    debug = app.config.get("DEBUG", False)

    print(f"[*] Starting SecureWeb on http://{host}:{port} (Environment: {env})")
    app.run(host=host, port=port, debug=debug)
