"""Unit tests for the model in the commit gate: its Git settings and the resident server."""

import os
import shutil
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

from leftblock import deep, server


def git(folder, *args):
    subprocess.run(["git", *args], cwd=folder, check=True, capture_output=True)


class SettingsTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.mkdtemp(prefix="leftblock-settings-")
        self.addCleanup(shutil.rmtree, self.folder, True)
        git(self.folder, "init", "-q")
        self.env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")

    def read(self):
        return deep.read_settings(self.folder, self.env)

    def test_defaults_are_off(self):
        settings = self.read()
        self.assertEqual(settings.mode, "off")
        self.assertEqual(settings.on_unavailable, "block")
        self.assertEqual(settings.idle_minutes, 60)
        self.assertEqual(settings.labels, deep.DEFAULT_LABELS)
        self.assertEqual(settings.threshold, deep.DEFAULT_THRESHOLD)

    def test_values_are_read_with_git_names(self):
        for key, value in [
            ("mode", "resident"), ("onUnavailable", "warn"), ("idleMinutes", "0"),
            ("labels", "private_person"), ("threshold", "0.5"),
        ]:
            git(self.folder, "config", "leftblock.deep." + key, value)
        settings = self.read()
        self.assertEqual(
            (settings.mode, settings.on_unavailable, settings.idle_minutes, settings.threshold),
            ("resident", "warn", 0, 0.5))
        self.assertIn("private_person", settings.labels)

    def test_invalid_values_name_their_key(self):
        for key, value in [
            ("mode", "always"), ("onUnavailable", "ignore"), ("idleMinutes", "-1"),
            ("labels", "nothing"), ("threshold", "2"),
        ]:
            git(self.folder, "config", "leftblock.deep." + key, value)
            with self.assertRaises(ValueError) as caught:
                self.read()
            self.assertIn("leftblock.deep." + key, str(caught.exception))
            git(self.folder, "config", "--unset", "leftblock.deep." + key)


class ServerFilesTests(unittest.TestCase):
    def setUp(self):
        self.base = tempfile.mkdtemp(prefix="lb-")
        self.addCleanup(shutil.rmtree, self.base, True)
        patcher = mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": self.base})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_directory_is_created_private(self):
        directory = server.runtime_directory()
        self.assertEqual(os.stat(directory).st_mode & 0o777, 0o700)

    def test_open_directory_is_refused(self):
        directory = os.path.join(self.base, "leftblock")
        os.makedirs(directory)
        os.chmod(directory, 0o750)
        with self.assertRaises(deep.Unavailable):
            server.runtime_directory()

    def test_socket_name_carries_the_version(self):
        with mock.patch.object(server, "leftblock_version", return_value="9.9.9"):
            path, lock, log = server.server_files()
        self.assertTrue(path.endswith("9.9.9.sock"))
        self.assertTrue(lock.endswith("9.9.9.lock") and log.endswith("9.9.9.log"))

    def test_overlong_path_is_unavailable(self):
        os.environ["XDG_RUNTIME_DIR"] = os.path.join(self.base, "x" * 120)
        with self.assertRaises(deep.Unavailable):
            server.server_files()


class ServerProtocolTests(unittest.TestCase):
    def setUp(self):
        self.base = tempfile.mkdtemp(prefix="lb-")
        self.addCleanup(shutil.rmtree, self.base, True)
        patcher = mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": self.base})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.path, _, _ = server.server_files()
        self.logged = []

    def start(self, detector, idle_minutes=0):
        import socket
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(self.path)
        listener.listen(4)
        self.addCleanup(listener.close)
        self.server = server.Server(detector, idle_minutes, self.logged.append)
        thread = threading.Thread(target=self.server.run, args=(listener,), daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(self.server.stopping.set)

    def test_ping_detect_and_stop(self):
        self.start(lambda text: [(0, 3, "secret", 0.97)])
        reply = server.ping(self.path)
        self.assertEqual(reply["model"], deep.MODEL)
        self.assertEqual(reply["revision"], deep.MODEL_REVISION)
        self.assertEqual(server.request(self.path, {"op": "detect", "text": "abc"})["spans"], [[0, 3, "secret", 0.97]])
        server.request(self.path, {"op": "stop"})
        self.assertTrue(self.server.stopping.wait(5))

    def test_errors_log_only_the_type_name(self):
        def failing(text):
            raise KeyError(text)
        self.start(failing)
        reply = server.request(self.path, {"op": "detect", "text": "private words"})
        self.assertEqual(reply, {"ok": False, "error": "KeyError"})
        self.assertEqual(self.logged, ["error KeyError"])

    def test_server_detector_returns_span_tuples(self):
        self.start(lambda text: [(1, 2, "secret", 0.95)])
        detector = server.ServerDetector()
        detector._path = self.path
        self.assertEqual(detector("xyz"), [(1, 2, "secret", 0.95)])

    def test_idle_server_exits(self):
        self.start(lambda text: [], idle_minutes=0.01)
        self.assertTrue(self.wait_for_log("idle exit"))

    def wait_for_log(self, event):
        import time
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if event in self.logged:
                return True
            time.sleep(0.05)
        return False


if __name__ == "__main__":
    unittest.main()
