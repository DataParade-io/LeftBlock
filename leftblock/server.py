"""Resident Privacy Filter server for the commit gate.

Loading the model takes seconds and its memory is large, so with
`leftblock.deep.mode` set to `resident` one background process holds it and
every commit asks that process. JSON lines over a Unix domain socket, one
request per connection:

    {"op": "ping"}                 -> protocol, leftblock version, model, revision, pid
    {"op": "detect", "text": ...}  -> spans [[start, end, label, score], ...]
    {"op": "stop"}                 -> the server exits

Staged text travels over this socket, so the socket lives in a private
directory owned by the current user, and the server never logs, stores or
echoes request text or spans: it logs lifecycle events and error type names.

`ServerDetector` is a callable with the same `detect(text) -> spans` shape as
the model itself, so `deep.scan` does not change. The first call starts the
server when none is running.
"""

import json
import os
import socket
import stat
import subprocess
import sys
import threading
import time

from leftblock import deep

PROTOCOL_VERSION = 1
MAX_SOCKET_PATH = 100
EXIT_MODEL_MISSING = 3
EXIT_EXTRA_MISSING = 4
EXIT_FAILED = 5
LOADING_NOTICE = (
    "Starting the Privacy Filter server and loading the model; "
    "this can take a few seconds the first time after a restart."
)
UNIX_SOCKETS_MESSAGE = (
    "Resident mode needs Unix domain sockets, which this platform lacks; "
    "set leftblock.deep.mode to per-commit."
)


def leftblock_version():
    try:
        from importlib.metadata import version
        return version("leftblock")
    except Exception:
        return "unknown"


# --- Where the socket lives -------------------------------------------------------

def runtime_directory():
    """The private directory for the socket, created if needed; Unavailable if unsafe."""
    if not hasattr(socket, "AF_UNIX") or not hasattr(os, "getuid"):
        raise deep.Unavailable(UNIX_SOCKETS_MESSAGE)
    base = os.environ.get("XDG_RUNTIME_DIR")
    if base:
        directory = os.path.join(base, "leftblock")
    else:
        directory = os.path.join(os.path.expanduser("~"), ".cache", "leftblock", "run")
    try:
        os.makedirs(directory, mode=0o700, exist_ok=True)
        info = os.lstat(directory)
    except OSError as exc:
        raise deep.Unavailable("Cannot use the server directory (%s)." % type(exc).__name__)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise deep.Unavailable(
            "The server directory %s must be a directory owned by you and closed to others "
            "(mode 0700); the Privacy Filter server was not used." % directory
        )
    return directory


def server_files(directory=None):
    """(socket, lock, log) paths; the leftblock version is in the name, so an upgrade starts a new server."""
    directory = directory or runtime_directory()
    name = os.path.join(directory, leftblock_version())
    paths = (name + ".sock", name + ".lock", name + ".log")
    if len(paths[0].encode("utf-8")) > MAX_SOCKET_PATH:
        raise deep.Unavailable(
            "The socket path is too long for this platform; set XDG_RUNTIME_DIR to a shorter directory."
        )
    return paths


# --- Talking to the server ---------------------------------------------------------

def request(path, payload):
    """Send one request and return the decoded reply. No timeout: a dead server ends the wait."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.connect(path)
        connection.sendall(json.dumps(payload).encode("utf-8") + b"\n")
        connection.shutdown(socket.SHUT_WR)
        data = b""
        while True:
            piece = connection.recv(65536)
            if not piece:
                break
            data += piece
    if not data:
        raise ConnectionError("the server closed the connection")
    return json.loads(data.decode("utf-8"))


def ping(path):
    """The server's ping reply, or None when nothing answers on the socket."""
    try:
        reply = request(path, {"op": "ping"})
    except (OSError, ValueError):
        return None
    if reply.get("ok") and reply.get("protocol") == PROTOCOL_VERSION:
        return reply
    return None


def _start_message(code, log):
    if code == EXIT_MODEL_MISSING:
        return deep.MODEL_MISSING_MESSAGE
    if code == EXIT_EXTRA_MISSING:
        return "Resident mode needs the optional model extra: " + deep.INSTALL_HINT
    return "The Privacy Filter server could not start (exit status %s); see %s." % (code, log)


def ensure_running(idle_minutes, notify=None):
    """The socket path of a running server, starting one if none answers.

    Concurrent callers queue on a lock file, so exactly one server is started.
    Waits for as long as the starting process is alive; Unavailable if it exits.
    """
    import fcntl
    path, lock_path, log_path = server_files()
    if ping(path):
        return path
    with open(lock_path, "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if ping(path):
            return path
        if os.path.exists(path):
            os.remove(path)
        if notify:
            notify(LOADING_NOTICE)
        with open(log_path, "a") as log:
            process = subprocess.Popen(
                [sys.executable, "-I", "-B", "-m", "leftblock.cli", "deep-server", "serve",
                 "--idle-minutes", str(idle_minutes)],
                cwd=os.path.dirname(path), stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                start_new_session=True,
            )
        while not ping(path):
            code = process.poll()
            if code is not None:
                raise deep.Unavailable(_start_message(code, log_path))
            time.sleep(0.05)
    return path


class ServerDetector:
    """`detect(text) -> spans` answered by the resident server, started on first use."""

    def __init__(self, idle_minutes=deep.DEFAULT_IDLE_MINUTES, notify=None):
        self.idle_minutes = idle_minutes
        self.notify = notify
        self._path = None

    def __call__(self, text):
        for attempt in (1, 2):
            if self._path is None:
                self._path = ensure_running(self.idle_minutes, self.notify)
            try:
                reply = request(self._path, {"op": "detect", "text": text})
            except (OSError, ValueError):
                # The server may have idled out between two calls; start it once more.
                self._path = None
                if attempt == 2:
                    raise deep.Unavailable("The Privacy Filter server stopped answering.")
                continue
            if not reply.get("ok"):
                raise deep.Unavailable("The Privacy Filter server failed (%s)." % reply.get("error", "error"))
            return [tuple(span) for span in reply["spans"]]


# --- The server ---------------------------------------------------------------------

class Server:
    def __init__(self, detector, idle_minutes, log):
        self.detector = detector
        self.idle_seconds = idle_minutes * 60
        self.log = log
        self.pipeline_lock = threading.Lock()
        self.stopping = threading.Event()
        self.active = 0
        self.last_activity = time.monotonic()
        self.counter_lock = threading.Lock()

    def handle(self, connection):
        try:
            with connection:
                data = b""
                while not data.endswith(b"\n"):
                    piece = connection.recv(65536)
                    if not piece:
                        break
                    data += piece
                reply = self.dispatch(json.loads(data.decode("utf-8")))
                connection.sendall(json.dumps(reply).encode("utf-8"))
        except Exception as exc:
            self.log("error " + type(exc).__name__)

    def dispatch(self, message):
        operation = message.get("op")
        if operation == "ping":
            return {
                "ok": True, "protocol": PROTOCOL_VERSION, "version": leftblock_version(),
                "model": deep.MODEL, "revision": deep.MODEL_REVISION, "pid": os.getpid(),
            }
        if operation == "stop":
            self.stopping.set()
            return {"ok": True}
        if operation == "detect":
            with self.counter_lock:
                self.active += 1
            try:
                with self.pipeline_lock:
                    spans = self.detector(message["text"])
                return {"ok": True, "spans": [list(span) for span in spans]}
            except Exception as exc:
                self.log("error " + type(exc).__name__)
                return {"ok": False, "error": type(exc).__name__}
            finally:
                with self.counter_lock:
                    self.active -= 1
                    self.last_activity = time.monotonic()
        return {"ok": False, "error": "unknown operation"}

    def idle(self):
        with self.counter_lock:
            quiet = time.monotonic() - self.last_activity
            return bool(self.idle_seconds) and not self.active and quiet > self.idle_seconds

    def run(self, listener):
        listener.settimeout(0.5)
        while not self.stopping.is_set():
            if self.idle():
                self.log("idle exit")
                return
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            threading.Thread(target=self.handle, args=(connection,), daemon=True).start()
        self.log("stop")


def serve(idle_minutes):
    """Run the server in this process until stopped or idle. Returns the exit status."""

    def log(event):
        print(time.strftime("%Y-%m-%dT%H:%M:%S") + " " + event, flush=True)

    def log_type_only(exc_type, exc, trace):
        log("error " + exc_type.__name__)

    sys.excepthook = log_type_only
    threading.excepthook = lambda args: log("error " + args.exc_type.__name__)
    log("start pid %d" % os.getpid())
    try:
        detector = deep.load_detector(None, deep.MODEL_REVISION, local_only=True)
        getattr(detector, "load", lambda: None)()
    except deep.ExtraMissing:
        log("error ExtraMissing")
        return EXIT_EXTRA_MISSING
    except deep.Unavailable as exc:
        log("error Unavailable")
        return EXIT_MODEL_MISSING if str(exc) == deep.MODEL_MISSING_MESSAGE else EXIT_FAILED
    except Exception as exc:
        log("error " + type(exc).__name__)
        return EXIT_FAILED
    path, _, _ = server_files()
    os.umask(0o177)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(path)
        os.chmod(path, 0o600)
        listener.listen(16)
        log("ready")
        Server(detector, idle_minutes, log).run(listener)
    finally:
        listener.close()
        if os.path.exists(path):
            os.remove(path)
    return 0


# --- Commands -----------------------------------------------------------------------

def status():
    """The ping reply of the running server, or None."""
    try:
        path, _, _ = server_files()
    except deep.Unavailable:
        return None
    return ping(path)


def stop():
    """Ask the server to exit and wait until it has. True if one was running."""
    path, _, _ = server_files()
    reply = ping(path)
    if not reply:
        return False
    try:
        request(path, {"op": "stop"})
    except (OSError, ValueError):
        pass
    while True:
        try:
            os.kill(reply["pid"], 0)
        except OSError:
            return True
        time.sleep(0.05)


def download(notify):
    """Fetch the pinned weights into the Hugging Face cache, saying how large they are."""
    try:
        from huggingface_hub import HfApi, snapshot_download
    except ImportError:
        raise deep.ExtraMissing()
    try:
        info = HfApi().model_info(deep.MODEL, revision=deep.MODEL_REVISION, files_metadata=True)
        size = sum(item.size or 0 for item in info.siblings)
        notify("Downloading %s at revision %s: about %.1f GB." % (
            deep.MODEL, deep.MODEL_REVISION[:12], size / 1e9))
        snapshot_download(deep.MODEL, revision=deep.MODEL_REVISION)
    except Exception as exc:
        raise deep.DeepScanError("Could not download the %s model (%s)." % (deep.MODEL, type(exc).__name__))
    notify("The %s model is ready." % deep.MODEL)
