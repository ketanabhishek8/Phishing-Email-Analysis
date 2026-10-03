"""Run the web app locally: python -m web [--port 5000] [--debug]"""

import argparse

from .app import create_app

parser = argparse.ArgumentParser(description="PhishKit web dashboard (binds to 127.0.0.1 only)")
parser.add_argument("--port", type=int, default=5000)
parser.add_argument("--debug", action="store_true", help="enable Flask debug mode")
args = parser.parse_args()

app = create_app()
print(f"PhishKit running at http://127.0.0.1:{args.port}")
app.run(host="127.0.0.1", port=args.port, debug=args.debug)
