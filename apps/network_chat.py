#!/usr/bin/env python3
"""LF-256 encrypted TCP chat."""

from __future__ import annotations

import argparse
import getpass
import json
import socket
import struct
import sys
import threading
import time
from pathlib import Path

from bootstrap import ensure_src

ensure_src()

from lf256 import (
    HybridSymmetricEngine,
    KEMDecapsulationError,
    LatticeFlux256,
    LF256KeyMap,
    PassphraseGuard,
    secure_compare,
)

DEFAULT_PORT = 37564
DEFAULT_HOST = "127.0.0.1"
HANDSHAKE_TIMEOUT_S = 30
QUIT_COMMANDS = frozenset({"/quit", "quit", "exit"})
MAX_FRAME_BYTES = 16 * 1024 * 1024


class ChatTransport:
    """Length-prefixed AEAD chat frames with monotonic sequence anti-replay."""

    def __init__(self, channel_key: bytes) -> None:
        self._key = channel_key
        self._send_seq = 0
        self._last_recv_seq = -1
        self._lock = threading.Lock()

    def pack_send(self, plaintext: bytes) -> bytes:
        with self._lock:
            seq = self._send_seq
            self._send_seq += 1
        payload = struct.pack(">Q", seq) + plaintext
        return HybridSymmetricEngine.encrypt(payload, self._key)

    def unpack_recv(self, blob: bytes) -> bytes:
        payload = HybridSymmetricEngine.decrypt(blob, self._key)
        if len(payload) < 8:
            raise ValueError("Invalid chat frame (missing sequence).")
        seq = struct.unpack(">Q", payload[:8])[0]
        with self._lock:
            if seq <= self._last_recv_seq:
                raise ValueError(
                    f"Replay detected: sequence {seq} <= last accepted {self._last_recv_seq}."
                )
            self._last_recv_seq = seq
        return payload[8:]


def prompt_passphrase() -> str:
    phrase = getpass.getpass(
        "Enter passphrase (manual only - not stored in keymap): "
    )
    if not phrase:
        raise ValueError("Passphrase cannot be empty.")
    return phrase


def send_frame(sock: socket.socket, payload: bytes) -> None:
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def recv_frame(sock: socket.socket) -> bytes:
    header = _recv_exact(sock, 4)
    length = struct.unpack(">I", header)[0]
    if length == 0 or length > MAX_FRAME_BYTES:
        raise ValueError(f"Invalid frame length: {length}")
    return _recv_exact(sock, length)


def _recv_exact(sock: socket.socket, nbytes: int) -> bytes:
    chunks: list[bytes] = []
    remaining = nbytes
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("Peer closed connection before frame completed.")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def send_json(sock: socket.socket, obj: dict) -> None:
    send_frame(sock, json.dumps(obj, separators=(",", ":")).encode("utf-8"))


def recv_json(sock: socket.socket) -> dict:
    return json.loads(recv_frame(sock).decode("utf-8"))


def kem_handshake_server(conn: socket.socket, engine: LatticeFlux256) -> bytes:
    server_time_ms = int(time.time() * 1000)
    public_key, private_key = engine.generate_keypair(t=server_time_ms)
    b_poly, t_anchor = public_key

    send_json(conn, {"phase": "kem_offer", "b": b_poly, "t": t_anchor})
    print(f"[handshake] Lattice KEM offer sent (t={t_anchor})")

    response = recv_json(conn)
    if response.get("phase") != "kem_response":
        raise ValueError(f"Expected kem_response, got: {response.get('phase')}")

    kem_ct = (response["u"], response["v"])
    confirm = bytes.fromhex(response["kem_confirm"])
    session_key = engine.decapsulate(kem_ct, private_key, expected_confirm=confirm)
    print("[handshake] Lattice session key established (KEM confirmed).")
    return session_key


def kem_handshake_client(sock: socket.socket, engine: LatticeFlux256) -> bytes:
    offer = recv_json(sock)
    if offer.get("phase") != "kem_offer":
        raise ValueError(f"Expected kem_offer, got: {offer.get('phase')}")

    public_key = (offer["b"], offer["t"])
    shared_secret, ciphertext, confirm = engine.encapsulate(public_key, current_t=offer["t"])
    u_poly, v_poly = ciphertext

    send_json(
        sock,
        {
            "phase": "kem_response",
            "u": u_poly,
            "v": v_poly,
            "kem_confirm": confirm.hex(),
        },
    )
    print("[handshake] Lattice session key established (KEM confirmed).")
    return shared_secret


def passphrase_handshake_server(
    conn: socket.socket, session_key: bytes, map_doc: dict, passphrase: str
) -> bytes:
    channel_key = LF256KeyMap.channel_key_from_network_map(
        session_key, map_doc, passphrase
    )
    proof = PassphraseGuard.proof_token(channel_key)
    send_json(conn, {"phase": "passphrase_challenge", "proof": proof})

    ack = recv_json(conn)
    if ack.get("phase") != "passphrase_proof" or not secure_compare(
        ack.get("proof", ""), proof
    ):
        raise ValueError(
            "Passphrase verification failed. Wrong passphrase or mismatched keymap."
        )
    print("[handshake] Passphrase verified (HKDF-bound channel key).")
    return channel_key


def passphrase_handshake_client(
    sock: socket.socket, session_key: bytes, map_doc: dict, passphrase: str
) -> bytes:
    challenge = recv_json(sock)
    if challenge.get("phase") != "passphrase_challenge":
        raise ValueError("Expected passphrase_challenge from server.")

    channel_key = LF256KeyMap.channel_key_from_network_map(
        session_key, map_doc, passphrase
    )
    proof = PassphraseGuard.proof_token(channel_key)
    if not secure_compare(proof, challenge.get("proof", "")):
        raise ValueError(
            "Passphrase verification failed. Wrong passphrase or mismatched keymap."
        )
    send_json(sock, {"phase": "passphrase_proof", "proof": proof})
    print("[handshake] Passphrase verified (HKDF-bound channel key).")
    return channel_key


def run_encrypted_chat(sock: socket.socket, channel_key: bytes, local_label: str) -> None:
    transport = ChatTransport(channel_key)
    sock.settimeout(None)
    stop = threading.Event()
    prompt = f"[{local_label}] "

    def receiver() -> None:
        try:
            while not stop.is_set():
                plaintext = transport.unpack_recv(recv_frame(sock))
                text = plaintext.decode("utf-8", errors="replace")
                if text.strip().lower() in QUIT_COMMANDS:
                    print("\n[peer] left the chat.")
                    stop.set()
                    return
                print(f"\n[peer] {text}")
                sys.stdout.write(prompt)
                sys.stdout.flush()
        except (ConnectionError, OSError, ValueError):
            if not stop.is_set():
                print("\n[peer] disconnected or frame rejected.")
                stop.set()

    threading.Thread(target=receiver, daemon=True).start()
    print(
        f"{prompt}Encrypted chat ready (AEAD + anti-replay). /quit to exit."
    )
    try:
        while not stop.is_set():
            try:
                line = input(prompt)
            except EOFError:
                break
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.lower() in QUIT_COMMANDS:
                try:
                    send_frame(sock, transport.pack_send(b"/quit"))
                except OSError:
                    pass
                break
            send_frame(sock, transport.pack_send(line.encode("utf-8")))
    except KeyboardInterrupt:
        print("\n[local] interrupted.")
    finally:
        stop.set()
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass


def run_server(
    host: str,
    port: int,
    map_doc: dict,
    label: str,
    passphrase: str,
    skew_ms: int | None,
) -> None:
    public_seed = LF256KeyMap.public_seed_from_map(map_doc)
    skew = skew_ms if skew_ms is not None else LF256KeyMap.allowed_skew_from_map(map_doc)
    engine = LatticeFlux256(public_seed=public_seed, allowed_skew_ms=skew)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, port))
        listener.listen(1)
        print(f"[server] Listening on {host}:{port} (skew={skew}ms)")

        conn, addr = listener.accept()
        with conn:
            conn.settimeout(HANDSHAKE_TIMEOUT_S)
            print(f"[server] Peer connected from {addr[0]}:{addr[1]}")
            session_key = kem_handshake_server(conn, engine)
            channel_key = passphrase_handshake_server(
                conn, session_key, map_doc, passphrase
            )
            run_encrypted_chat(conn, channel_key, label)


def run_client(
    host: str,
    port: int,
    map_doc: dict,
    label: str,
    passphrase: str,
    skew_ms: int | None,
) -> None:
    public_seed = LF256KeyMap.public_seed_from_map(map_doc)
    skew = skew_ms if skew_ms is not None else LF256KeyMap.allowed_skew_from_map(map_doc)
    engine = LatticeFlux256(public_seed=public_seed, allowed_skew_ms=skew)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(HANDSHAKE_TIMEOUT_S)
        print(f"[client] Connecting to {host}:{port} (skew={skew}ms)...")
        sock.connect((host, port))
        session_key = kem_handshake_client(sock, engine)
        channel_key = passphrase_handshake_client(
            sock, session_key, map_doc, passphrase
        )
        run_encrypted_chat(sock, channel_key, label)


def cmd_init_map(out: Path, seed_hex: str | None, skew_ms: int | None) -> None:
    public_seed = bytes.fromhex(seed_hex) if seed_hex else None
    if seed_hex and len(public_seed) != 32:
        raise ValueError("--seed-hex must be 64 hex characters (32 bytes).")
    doc = LF256KeyMap.create_network_map(public_seed, allowed_skew_ms=skew_ms)
    LF256KeyMap.save_map(out, doc)
    print(f"[init-map] Wrote v2.1 map: {out}")
    print("[init-map] Distribute this file to all peers.")
    print("[init-map] Passphrase is entered manually at runtime (never in map).")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="LF-256 v2.1 chat: AEAD, KEM confirm, HKDF passphrase bind.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    init_p = sub.add_parser("init-map", help="Create shared network map (v2.1).")
    init_p.add_argument("--out", required=True, type=Path)
    init_p.add_argument("--seed-hex", default=None)
    init_p.add_argument(
        "--skew-ms",
        type=int,
        default=None,
        help=f"Clock skew window (default {LatticeFlux256.DEFAULT_SKEW_MS} ms).",
    )

    for role in ("server", "client"):
        p = sub.add_parser(role, help=f"Run encrypted chat as {role}.")
        p.add_argument("--keymap", required=True, type=Path)
        p.add_argument(
            "--host",
            default=None,
            help="Server: listen address (default 127.0.0.1). Client: remote host.",
        )
        p.add_argument(
            "--listen-all",
            action="store_true",
            help="Server only: bind 0.0.0.0 (exposes chat on all interfaces).",
        )
        p.add_argument("--port", "-p", type=int, default=DEFAULT_PORT)
        p.add_argument("--name", default=None)
        p.add_argument("--skew-ms", type=int, default=None)

    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    if args.command == "init-map":
        cmd_init_map(args.out, args.seed_hex, args.skew_ms)
        return 0

    map_doc = LF256KeyMap.load_map(args.keymap)
    if map_doc.get("kind") != "network":
        raise ValueError(
            f"Keymap kind is '{map_doc.get('kind')}', expected 'network' for chat."
        )

    print(f"[keymap] Imported v2.1 map: {args.keymap}")
    passphrase = prompt_passphrase()
    label = args.name or args.command
    skew = getattr(args, "skew_ms", None)

    if args.command == "server":
        listen_host = "0.0.0.0" if args.listen_all else (args.host or "127.0.0.1")
        run_server(listen_host, args.port, map_doc, label, passphrase, skew)
    else:
        run_client(args.host or DEFAULT_HOST, args.port, map_doc, label, passphrase, skew)

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        KeyboardInterrupt,
        ConnectionError,
        socket.timeout,
        ValueError,
        OSError,
        KEMDecapsulationError,
    ) as exc:
        print(f"[error] {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
