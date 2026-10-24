
import os
from trustvault import create_app

env = os.getenv("FLASK_ENV", "development")
app = create_app(env)

if __name__ == "__main__":
    if env == "development":
        from trustvault.models.base import db

        with app.app_context():
            db.create_all()

    app.run(host="127.0.0.1", port=5000, debug=False)
