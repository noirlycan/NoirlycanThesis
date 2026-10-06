"""Windows desktop entry point for the existing collection runtime."""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import queue
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

from noirlycan_core.runtime.agent_identity import load_agent_credentials, save_agent_credentials
from noirlycan_core.storage.atomic_io import atomic_write_text
from noirlycan_core.storage.log_store import new_session_log_path


def normalize_server(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("Enter the server address.")
    if "://" not in value:
        value = "http://" + value
    parsed = urlsplit(value)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username or parsed.password or parsed.query or parsed.fragment
            or parsed.path not in {"", "/"} or any(c.isspace() for c in value)):
        raise ValueError("Use a server address such as https://server or http://IP:port.")
    try:
        parsed.port
    except ValueError as exc:
        raise ValueError("Invalid server port.") from exc
    return value.rstrip("/")


def enrollment_agent_id(server: str, token: str) -> str:
    """Identify a pre-registered agent without requiring an ID in the UI."""
    request = urllib.request.Request(
        normalize_server(server) + "/api/ingest/enrollment",
        data=b"{}", method="POST",
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            payload = json.load(response)
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            raise ValueError("The token is invalid or has been revoked.") from exc
        if exc.code == 404:
            raise ValueError("The backend does not support the desktop Agent. Update the backend.") from exc
        raise ValueError(f"The server returned HTTP error {exc.code}.") from exc
    agent_id = payload.get("agent_id") if isinstance(payload, dict) else None
    if not isinstance(agent_id, str) or not agent_id.strip():
        raise ValueError("The server did not return a valid Agent ID.")
    return agent_id.strip()


def application_directory() -> Path:
    base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / ".local" / "share")
    directory = base / "Noirlycan"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def server_logs(directory: Path, server: str) -> Path:
    # Separate credentials and signing-key pins when switching servers.
    return directory / "servers" / hashlib.sha256(server.encode()).hexdigest()[:20] / "logs"


def ensure_administrator() -> bool:
    """Request UAC for source launches too; packaged EXEs use requireAdministrator."""
    if sys.platform != "win32" or ctypes.windll.shell32.IsUserAnAdmin():
        return True
    parameters = "" if getattr(sys, "frozen", False) else subprocess.list2cmdline(
        ["-m", "noirlycan_agent.desktop"]
    )
    shell_execute = ctypes.windll.shell32.ShellExecuteW
    shell_execute.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_wchar_p,
                              ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_int]
    shell_execute.restype = ctypes.c_void_p
    result = shell_execute(None, "runas", sys.executable, parameters, None, 1)
    if not result or result <= 32:
        raise OSError("Administrator access was not granted. Reopen the application and accept the UAC prompt.")
    return False


class DesktopLog:
    """Bounded UI log; worker threads never access Tk widgets."""

    encoding = "utf-8"

    def __init__(self, events: queue.Queue, secret: str = "") -> None:
        self.events = events
        self.secret = secret

    def write(self, value: str) -> int:
        safe = value.replace(self.secret, "[TOKEN]") if self.secret else value
        if safe.strip():
            try:
                self.events.put_nowait(("log", safe))
            except queue.Full:
                pass
        return len(value)

    def flush(self) -> None:
        pass

    def isatty(self) -> bool:
        return False


class AgentDesktop:
    def __init__(self, root) -> None:
        import tkinter as tk
        from tkinter import ttk
        from tkinter.scrolledtext import ScrolledText

        self.root = root
        self.directory = application_directory()
        self.settings_path = self.directory / "desktop.json"
        try:
            saved = json.loads(self.settings_path.read_text(encoding="utf-8"))
            saved_server = normalize_server(saved.get("server", ""))
        except (OSError, ValueError, AttributeError):
            saved_server = ""
        credentials = load_agent_credentials(server_logs(self.directory, saved_server)) if saved_server else {}
        self.events: queue.Queue = queue.Queue(maxsize=1000)
        self.stop_event = threading.Event()
        self.worker: threading.Thread | None = None
        self.agent = None
        self.closing = False
        self.server = tk.StringVar(value=saved_server)
        self.token = tk.StringVar(value=credentials.get("token", ""))
        self.status = tk.StringVar(value="Ready — Administrator" if sys.platform == "win32"
                                  else "Ready — Development mode")
        self.identity = tk.StringVar(value=credentials.get("agent_id", "Not connected"))
        root.title("Noirlycan Agent")
        root.geometry("700x530")
        root.minsize(580, 430)
        frame = ttk.Frame(root, padding=24)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="Noirlycan Agent", font=("Segoe UI", 20, "bold")).pack(anchor="w")
        ttk.Label(frame, text="Connect this machine to the central management server.").pack(anchor="w", pady=(4, 20))
        ttk.Label(frame, text="Server").pack(anchor="w")
        self.server_entry = ttk.Entry(frame, textvariable=self.server)
        self.server_entry.pack(fill="x", pady=(4, 12))
        ttk.Label(frame, text="Agent enrollment token").pack(anchor="w")
        self.token_entry = ttk.Entry(frame, textvariable=self.token, show="*")
        self.token_entry.pack(fill="x", pady=(4, 14))
        buttons = ttk.Frame(frame)
        buttons.pack(fill="x")
        self.start_button = ttk.Button(buttons, text="Connect and start", command=self.start)
        self.start_button.pack(side="left")
        self.stop_button = ttk.Button(buttons, text="Stop Agent", command=self.stop, state="disabled")
        self.stop_button.pack(side="left", padx=8)
        ttk.Button(buttons, text="Open data folder", command=self.open_data).pack(side="right")
        ttk.Label(frame, textvariable=self.status, wraplength=620).pack(anchor="w", pady=(18, 4))
        ttk.Label(frame, textvariable=self.identity).pack(anchor="w", pady=(0, 12))
        self.log = ScrolledText(frame, height=10, font=("Consolas", 9), state="disabled", wrap="word")
        self.log.pack(fill="both", expand=True)
        root.protocol("WM_DELETE_WINDOW", self.close)
        root.after(200, self.poll)

    def start(self) -> None:
        from tkinter import messagebox
        try:
            server = normalize_server(self.server.get())
            token = self.token.get().strip()
            if not token or not token.isascii() or any(c.isspace() for c in token):
                raise ValueError("Enter a valid Agent enrollment token from the dashboard.")
        except ValueError as exc:
            messagebox.showerror("Connection settings", str(exc), parent=self.root)
            return
        if self.worker is not None and self.worker.is_alive():
            return
        self.server.set(server)
        self.agent = None
        self.stop_event.clear()
        self.set_running(True)
        self.status.set("Authenticating and starting Agent…")
        self.worker = threading.Thread(target=self.run, args=(server, token), name="desktop-agent")
        self.worker.start()

    def run(self, server: str, token: str) -> None:
        from contextlib import redirect_stderr, redirect_stdout

        output = DesktopLog(self.events, token)
        try:
            with redirect_stdout(output), redirect_stderr(output):
                from noirlycan_agent.cli import build_parser
                from noirlycan_agent.runtime.collector import run_collector

                agent_id = enrollment_agent_id(server, token)
                if self.stop_event.is_set():
                    return
                logs = server_logs(self.directory, server)
                save_agent_credentials(agent_id, logs, token=token, require_protection=sys.platform == "win32")
                atomic_write_text(self.settings_path, json.dumps({"server": server}) + "\n")
                args = build_parser().parse_args(["run", "--watch-sysmon", "--auto-attach-new-processes"])
                args.server, args.agent_id = server, agent_id
                args.jsonl = new_session_log_path(logs)
                args.require_console = True
                run_collector(args, stop_event=self.stop_event,
                              on_ready=lambda agent: self.events.put(("ready", agent)))
        except Exception as exc:
            self.events.put(("error", str(exc).replace(token, "[TOKEN]")))
        finally:
            self.events.put(("finished", None))

    def set_running(self, running: bool) -> None:
        self.start_button.configure(state="disabled" if running else "normal")
        self.stop_button.configure(state="normal" if running else "disabled")
        for entry in (self.server_entry, self.token_entry):
            entry.configure(state="disabled" if running else "normal")

    def stop(self) -> None:
        self.stop_event.set()
        self.stop_button.configure(state="disabled")
        self.status.set("Stopping Agent and closing the connection…")

    def close(self) -> None:
        self.closing = True
        if self.worker and self.worker.is_alive():
            self.stop()
        else:
            self.root.destroy()

    def poll(self) -> None:
        from tkinter import messagebox
        for _ in range(200):
            try:
                kind, value = self.events.get_nowait()
            except queue.Empty:
                break
            if kind == "ready":
                self.agent = value
                self.identity.set("Agent ID: " + value.console.agent_id)
            elif kind == "log":
                self.log.configure(state="normal")
                self.log.insert("end", value.rstrip() + "\n")
                if int(self.log.index("end-1c").split(".")[0]) > 500:
                    self.log.delete("1.0", "100.0")
                self.log.see("end")
                self.log.configure(state="disabled")
            elif kind == "error":
                self.status.set("Error: " + value)
                if not self.closing:
                    messagebox.showerror("Agent", value, parent=self.root)
            elif kind == "finished":
                self.agent = None
                self.set_running(False)
                if not self.status.get().startswith("Error:"):
                    self.status.set("Agent stopped.")
        if self.closing and (self.worker is None or not self.worker.is_alive()):
            self.root.destroy()
            return
        if self.agent is not None and not self.stop_event.is_set():
            age = time.monotonic() - self.agent.console.last_success
            self.status.set("Agent running — Connected to server" if age < 20
                            else "Agent running — Server unavailable, retrying")
        self.root.after(200, self.poll)

    def open_data(self) -> None:
        if sys.platform == "win32":
            os.startfile(self.directory)


def main() -> int:
    import tkinter as tk
    from tkinter import messagebox

    if sys.argv[1:] == ["--smoke-test"]:
        return packaged_smoke_test()
    try:
        if not ensure_administrator():
            return 0
    except OSError as exc:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Administrator access", str(exc), parent=root)
        root.destroy()
        return 1
    # Keep a single desktop collector alive per interactive Windows session.
    mutex = None
    if sys.platform == "win32":
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
        kernel.CreateMutexW.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        mutex = kernel.CreateMutexW(None, False, "Local\\NoirlycanAgentDesktop")
        if not mutex:
            raise ctypes.WinError(ctypes.get_last_error())
        if ctypes.get_last_error() == 183:
            kernel.CloseHandle(mutex)
            root = tk.Tk()
            root.withdraw()
            messagebox.showinfo("Noirlycan Agent", "The Agent application is already open.", parent=root)
            root.destroy()
            return 0
    try:
        root = tk.Tk()
        AgentDesktop(root)
        root.mainloop()
    finally:
        if mutex:
            kernel.CloseHandle(mutex)
    return 0


def packaged_smoke_test() -> int:
    """Build verification: exercise GUI, bundled sensors/hooks, signing and DPAPI."""
    import tempfile
    import tkinter as tk
    try:
        from noirlycan_agent.runtime import collector  # noqa: F401 - verify frozen import graph
        from noirlycan_agent.sensors.frida_monitor import load_default_hook_script
        from noirlycan_core.runtime.command_signing import CommandSigner

        if sys.platform == "win32":
            import win32evtlog  # noqa: F401
            if not ctypes.windll.shell32.IsUserAnAdmin():
                return 1
        import frida
        frida.get_local_device()
        assert "globalThis" in load_default_hook_script()
        with tempfile.TemporaryDirectory(prefix="noirlycan-build-check-") as temporary:
            directory = Path(temporary)
            save_agent_credentials("build-check", directory, token="build-check-token",
                                   require_protection=sys.platform == "win32")
            assert load_agent_credentials(directory)["token"] == "build-check-token"
            assert CommandSigner.load_or_create(directory).public_key
        root = tk.Tk()
        root.withdraw()
        AgentDesktop(root)
        root.update()
        root.destroy()
    except Exception:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
