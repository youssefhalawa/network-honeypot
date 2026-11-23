"""
Small helper shared by the HTTP decoy and the dashboard (Member 1):
run a Flask app on Werkzeug's threaded server until a stop event is set,
so app/main.py can shut everything down cleanly.
"""
import threading

from werkzeug.serving import make_server


def serve_until_stopped(flask_app, host, port, stop_event=None, request_handler=None):
    server = make_server(host, port, flask_app, threaded=True, request_handler=request_handler)
    if stop_event is not None:
        def _watch():
            stop_event.wait()
            server.shutdown()
        threading.Thread(target=_watch, daemon=True, name=f'stop-{port}').start()
    try:
        server.serve_forever()
    finally:
        server.server_close()
