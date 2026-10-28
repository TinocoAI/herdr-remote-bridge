#!/usr/bin/env python3
"""Herdr Remote Bridge V1: context-aware session/listener preparation."""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shlex
import socket
import subprocess
import sys
import time
from pathlib import Path

PLUGIN = "herdr-remote-bridge"
TOKEN_TTL = 300
TOKEN_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
HERDR = os.environ.get("HERDR_BIN_PATH", "herdr")


def state_dir() -> Path:
    path = os.environ.get("HERDR_PLUGIN_STATE_DIR")
    if path:
        return Path(path)
    return Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state")) / "herdr" / "plugins" / PLUGIN


def state_path() -> Path:
    return state_dir() / "pending.json"


def run_herdr(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run([HERDR, *args], text=True, capture_output=True, timeout=20)


def current_pane() -> tuple[str | None, str | None]:
    try:
        result = run_herdr(["pane", "current"])
        if result.returncode:
            return None, None
        pane = json.loads(result.stdout)["result"]["pane"]
        return pane.get("pane_id"), pane.get("tab_id")
    except (OSError, subprocess.SubprocessError, ValueError, KeyError):
        return None, None


def process_info(pane_id: str) -> dict:
    try:
        result = run_herdr(["pane", "process-info", "--pane", pane_id])
        if result.returncode:
            return {}
        return json.loads(result.stdout)["result"]["process_info"]
    except (OSError, subprocess.SubprocessError, ValueError, KeyError):
        return {}


def parse_ssh(argv: list[str]) -> dict | None:
    """Parse the focused pane's ssh argv, following SCP Explorer's rules."""
    if not argv or argv[0] not in {"ssh", "ssh.exe"}:
        return None
    args = argv[1:]
    target = None
    port = None
    jump = None
    value_flags = {"-p", "-J", "-o", "-i", "-F", "-c", "-b", "-m", "-L", "-R", "-D", "-l", "-S"}
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in {"-p", "-J"}:
            value = args[i + 1] if i + 1 < len(args) else None
            if arg == "-p":
                port = value
            else:
                jump = value
            i += 2
            continue
        if arg.startswith("-"):
            i += 2 if arg in value_flags else 1
            continue
        target = arg
        break
    if not target:
        return None
    return {"target": target, "port": port, "jump": jump}


def detect_context() -> dict:
    pane_id, tab_id = current_pane()
    if not pane_id:
        return {"kind": "local", "listener_host": "local", "source_pane": None, "ssh": None, "tab_id": tab_id}
    info = process_info(pane_id)
    for proc in info.get("foreground_processes", []):
        ssh = parse_ssh(proc.get("argv", []))
        if ssh:
            return {"kind": "ssh", "listener_host": ssh["target"], "source_pane": pane_id, "ssh": ssh, "tab_id": tab_id}
    return {"kind": "local", "listener_host": "local", "source_pane": pane_id, "ssh": None, "tab_id": tab_id}


def make_session() -> tuple[str, str, str]:
    session = secrets.token_hex(8)
    token = "".join(secrets.choice(TOKEN_ALPHABET) for _ in range(6))
    digest = hashlib.sha256(token.encode()).hexdigest()
    return session, token, digest


def free_local_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def prepare_remote(target: str, session: str, digest: str) -> bool:
    """Register the one-use token digest on the gateway."""
    path = f"/tmp/herdr-bridge-{session}.sha256"
    cmd = f"umask 077; printf '%s\\n' '{digest}' > '{path}'; chmod 600 '{path}'"
    try:
        result = subprocess.run(
            ["ssh", "-o", "ConnectTimeout=10", target, cmd],
            text=True, timeout=30,
        )
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def public_target(target: str) -> str:
    """Return a configured target; otherwise keep the SSH control target.

    The pane performs remote egress discovery before printing the bootstrap
    command. This function intentionally contains no environment-specific IPs.
    """
    return os.environ.get("HERDR_BRIDGE_PUBLIC_TARGET", "").strip() or target


def discover_public_target(target: str) -> str | None:
    """Discover the selected host's source IP for the default internet route."""
    try:
        result = subprocess.run(
            ["ssh", "-o", "ConnectTimeout=10", target, "ip -4 route get 1.1.1.1"],
            capture_output=True, text=True, timeout=20,
        )
        if result.returncode:
            return None
        match = re.search(r"\bsrc\s+(\d{1,3}(?:\.\d{1,3}){3})\b", result.stdout)
        if not match:
            return None
        user = target.split("@", 1)[0] + "@" if "@" in target else ""
        return user + match.group(1)
    except (OSError, subprocess.SubprocessError):
        return None


def action() -> int:
    context = detect_context()
    session, token, digest = make_session()
    now = int(time.time())
    remote_port = 20000 + secrets.randbelow(18000)
    local_port = free_local_port()
    target = (context.get("ssh") or {}).get("target") or ""
    public = public_target(target)
    prepared = True
    state_dir().mkdir(parents=True, exist_ok=True)
    state_path().write_text(json.dumps({
        "plugin": PLUGIN, "session": session, "token_sha256": digest,
        "created_unix": now, "expires_unix": now + TOKEN_TTL,
        "status": "waiting", "context": context,
        "remote_port": remote_port, "local_port": local_port,
        "remote_prepared": prepared,
    }, indent=2) + "\n")
    env = {
        "BRIDGE_SESSION": session, "BRIDGE_TOKEN": token,
        "BRIDGE_CONTEXT": context["kind"], "BRIDGE_LISTENER_HOST": context["listener_host"],
        "BRIDGE_SOURCE_PANE": context.get("source_pane") or "",
        "BRIDGE_SSH_TARGET": target, "BRIDGE_PUBLIC_TARGET": public,
        "BRIDGE_TOKEN_SHA256": digest,
        "BRIDGE_REMOTE_PORT": str(remote_port), "BRIDGE_LOCAL_PORT": str(local_port),
        "BRIDGE_PREPARED": str(prepared).lower(),
    }
    args = ["plugin", "pane", "open", "--plugin", PLUGIN, "--entrypoint", "wait",
            "--placement", "popup", "--focus"]
    for key, value in env.items():
        args.extend(["--env", f"{key}={value}"])
    try:
        result = run_herdr(args)
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"remote bridge: failed to open waiting pane: {exc}", file=sys.stderr)
        return 1
    if result.returncode:
        print(result.stderr or result.stdout, file=sys.stderr, end="")
    return result.returncode


def copy_to_clipboard(text: str) -> bool:
    """Copy text using the native clipboard tool when available."""
    commands = [["pbcopy"], ["wl-copy"], ["xclip", "-selection", "clipboard"], ["xsel", "--clipboard", "--input"]]
    for command in commands:
        try:
            result = subprocess.run(command, input=text, text=True, capture_output=True, timeout=3)
            if result.returncode == 0:
                return True
        except (OSError, subprocess.SubprocessError):
            continue
    return False


def start_controller(target: str, local_port: str, remote_port: str, remote_user: str, source_pane: str, controller_pane: str) -> None:
    """Keep a local SSH forward and open the second pane when it becomes live."""
    forward = subprocess.Popen([
        "ssh", "-N", "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=3", "-o", "TCPKeepAlive=yes",
        "-L", f"127.0.0.1:{local_port}:127.0.0.1:{remote_port}", target,
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    connected = False
    try:
        deadline = time.time() + TOKEN_TTL
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", int(local_port)), timeout=1) as probe:
                    probe.settimeout(2)
                    if not probe.recv(32).startswith(b"SSH-"):
                        raise OSError("forward endpoint is not an SSH server yet")
                    if not source_pane:
                        raise OSError("original pane is unavailable")
                    run_herdr(["pane", "send-text", source_pane, "exit\n"])
                    time.sleep(1)
                    run_herdr(["pane", "run", source_pane, f"ssh -tt -p {local_port} {remote_user}@127.0.0.1"])
                    if controller_pane:
                        run_herdr(["pane", "close", controller_pane])
                    connected = True
                    return
            except (OSError, ValueError, KeyError, subprocess.SubprocessError):
                time.sleep(2)
    finally:
        if not connected and forward.poll() is None:
            forward.terminate()


def pane() -> int:
    context = os.environ.get("BRIDGE_CONTEXT", "local")
    host = os.environ.get("BRIDGE_LISTENER_HOST", "local")
    target = os.environ.get("BRIDGE_SSH_TARGET", "")
    source_pane = os.environ.get("BRIDGE_SOURCE_PANE", "")
    controller_pane = os.environ.get("HERDR_PANE_ID", "")
    public = os.environ.get("BRIDGE_PUBLIC_TARGET", target)
    if context == "ssh" and not os.environ.get("HERDR_BRIDGE_PUBLIC_TARGET"):
        discovered = discover_public_target(target)
        if discovered:
            public = discovered

    session = os.environ.get("BRIDGE_SESSION", "unknown")
    token = os.environ.get("BRIDGE_TOKEN", "")
    digest = os.environ.get("BRIDGE_TOKEN_SHA256", "")
    remote_port = os.environ.get("BRIDGE_REMOTE_PORT", "")
    local_port = os.environ.get("BRIDGE_LOCAL_PORT", "")
    prepared = os.environ.get("BRIDGE_PREPARED") == "true"
    remote_user = os.environ.get("HERDR_BRIDGE_REMOTE_USER", "root")
    if context == "ssh" and target:
        prepared = prepare_remote(target, session, digest)
        try:
            print(f"Utilizador na máquina remota [{remote_user}]: ", end="", flush=True)
            entered = sys.stdin.readline().strip()
            if entered:
                remote_user = entered
        except (EOFError, OSError):
            pass
    print("Herdr Remote Bridge V1", flush=True)
    print("======================", flush=True)
    print("", flush=True)
    print(f"Contexto detetado: {'SSH' if context == 'ssh' else 'shell local'}", flush=True)
    print(f"Listener associado a: {host}", flush=True)
    print(f"Session: {session}", flush=True)
    print("", flush=True)
    if context == "ssh" and not prepared:
        print("ERRO: não foi possível preparar o listener no host SSH.", flush=True)
    elif context == "ssh":
        print("No terminal web remoto, executa este comando:", flush=True)
        print("", flush=True)
        first = shlex.join(["ssh", "-tt", "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=3", public, "herdr-bridge", "auth", session])
        second = shlex.join([
            "ssh", "-tt", "-o", "ExitOnForwardFailure=yes",
            "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=3", "-o", "TCPKeepAlive=yes",
            "-R", f"127.0.0.1:{remote_port}:127.0.0.1:22", public,
            "herdr-bridge", "hold", session,
        ])
        command = first + " && " + second
        print(f"  {command}", flush=True)
        copied = copy_to_clipboard(command)
        print("(comando copiado para o clipboard)" if copied else "(clipboard indisponível; escreve o comando manualmente)", flush=True)
        print("", flush=True)
        print(f"Token: {token}", flush=True)
        print(f"O Herdr fará o forward local em 127.0.0.1:{local_port}.", flush=True)
    else:
        print("Listener local preparado; o transporte local será activado no próximo passo.", flush=True)
    print("", flush=True)
    print("A aguardar a ligação segura...", flush=True)
    if context == "ssh" and prepared and target and local_port and remote_port:
        start_controller(target, local_port, remote_port, remote_user, source_pane, controller_pane)
    while True:
        time.sleep(60)


def self_test() -> int:
    a = make_session()
    b = make_session()
    assert a[0] != b[0] and a[1] != b[1]
    assert len(a[1]) == 6 and set(a[1]) <= set(TOKEN_ALPHABET)
    assert hashlib.sha256(a[1].encode()).hexdigest() == a[2]
    assert parse_ssh(["ssh", "-p", "2222", "root@vps"]) == {"target": "root@vps", "port": "2222", "jump": None}
    assert parse_ssh(["zsh"]) is None
    assert public_target("root@control-host") == "root@control-host"
    print("self-test: ok")
    return 0


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in {"action", "pane", "--self-test"}:
        print("usage: bridge.py action|pane|--self-test", file=sys.stderr)
        return 2
    return {"action": action, "pane": pane, "--self-test": self_test}[argv[1]]()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
