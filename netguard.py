"""Network kill switch.

FileLocker never needs the network. `install()` runs first thing at startup
(main.py) and replaces Python's socket entry points with functions that raise
NetworkBlockedError, so no code in this process - ours or a bundled library's -
can open a connection or resolve a host name through Python.

This is defence in depth on top of the fact that the code contains no networking
logic (enforced by tests/test_no_network.py). It cannot stop native code calling
Windows' networking DLLs directly; for a hard OS-level guarantee, IT can add an
outbound Windows Firewall block rule for FileLocker.exe (see VERIFYING.md).
"""

from __future__ import annotations

import socket as _socket_mod

try:
    import _socket as _c_socket  # the C module behind `socket`
except ImportError:  # pragma: no cover
    _c_socket = None


class NetworkBlockedError(OSError):
    """Raised for any attempt to use the network while the guard is installed."""


_installed = False


def _blocked(*_args, **_kwargs):
    raise NetworkBlockedError("Network access is disabled in FileLocker (offline tool)")


class _BlockedSocket:
    """Stand-in for socket.socket: refuses to be created."""

    def __new__(cls, *args, **kwargs):
        _blocked()


_BLOCKED_FUNCTIONS = (
    "create_connection",
    "create_server",
    "getaddrinfo",
    "gethostbyname",
    "gethostbyname_ex",
    "gethostbyaddr",
    "getnameinfo",
    "getfqdn",
    "socketpair",
    "fromfd",
)


def install() -> None:
    """Disable all socket-level networking in this process. Idempotent."""
    global _installed
    if _installed:
        return
    for mod in (_socket_mod, _c_socket):
        if mod is None:
            continue
        for cls_name in ("socket", "SocketType"):
            if hasattr(mod, cls_name):
                setattr(mod, cls_name, _BlockedSocket)
        for fn in _BLOCKED_FUNCTIONS:
            if hasattr(mod, fn):
                setattr(mod, fn, _blocked)
    _installed = True


def is_installed() -> bool:
    return _installed
