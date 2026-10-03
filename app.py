"""WSGI entry point for hosting the web app (Vercel, gunicorn, etc.).

    gunicorn app:app

Hosted mode is enabled automatically on Vercel (VERCEL is set) or with PHISHKIT_HOSTED=1.
For local use, run `python -m web` instead.
"""

from web.app import create_app

app = create_app()
