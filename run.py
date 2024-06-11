from app import create_app
import threading
from honeypot.honeypot import start_honeypot

if __name__ == "__main__":
    app = create_app()
    honeypot_thread = threading.Thread(target=start_honeypot)
    honeypot_thread.start()
    app.run(debug=True)
