import os
from trustvault import create_app
from trustvault.models.base import db

env = os.getenv("FLASK_ENV", "development")
app = create_app(env)

# Auto-create tables in development mode if not existing
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
