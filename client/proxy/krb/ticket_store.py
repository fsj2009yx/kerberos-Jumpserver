"""Ticket persistence using a compact binary on-disk format."""

import os
import struct
import time
from typing import Any, Dict, Optional, Tuple


MAGIC = b"KTV1"
MAX_STORE_BYTES = 1024 * 1024


def _pack_u16_blob(value: bytes) -> bytes:
    if len(value) > 0xFFFF:
        raise ValueError("field too large")
    return struct.pack(">H", len(value)) + value


def _pack_u32_blob(value: bytes) -> bytes:
    if len(value) > 0xFFFFFFFF:
        raise ValueError("field too large")
    return struct.pack(">I", len(value)) + value


def _pack_u32(value: int) -> bytes:
    if value < 0 or value > 0xFFFFFFFF:
        raise ValueError("timestamp out of range")
    return struct.pack(">I", value)


def _read_exact(raw: bytes, offset: int, size: int) -> Tuple[bytes, int]:
    end = offset + size
    if end > len(raw):
        raise ValueError("truncated ticket store")
    return raw[offset:end], end


def _read_u16_blob(raw: bytes, offset: int) -> Tuple[bytes, int]:
    length_raw, offset = _read_exact(raw, offset, 2)
    length = struct.unpack(">H", length_raw)[0]
    return _read_exact(raw, offset, length)


def _read_u32_blob(raw: bytes, offset: int) -> Tuple[bytes, int]:
    length_raw, offset = _read_exact(raw, offset, 4)
    length = struct.unpack(">I", length_raw)[0]
    return _read_exact(raw, offset, length)


def _build_store_blob(bundle: Any, client_id: str, service_id: str) -> bytes:
    client_id_raw = client_id.encode("utf-8")
    service_id_raw = service_id.encode("utf-8")

    return b"".join([
        MAGIC,
        _pack_u16_blob(client_id_raw),
        _pack_u16_blob(service_id_raw),
        _pack_u32(int(bundle.tgt_expire)),
        _pack_u32(int(bundle.tv_expire)),
        _pack_u16_blob(bundle.key_c_tgs or b""),
        _pack_u32_blob(bundle.ticket_tgs or b""),
        _pack_u16_blob(bundle.key_c_v or b""),
        _pack_u32_blob(bundle.ticket_v or b""),
    ])


def save_tickets(bundle: Any, client_id: str, service_id: str, path: str) -> None:
    """Serialize TicketBundle to a binary file.

    The file stores the service-ticket material as bytes instead of JSON/base64.
    Key_c_v is persisted together with Ticket_V because AP_REQ must generate a
    fresh authenticator encrypted by Key_c_v when reusing an unexpired Ticket_V.
    """
    if not path:
        return

    raw = _build_store_blob(bundle, client_id, service_id)

    parent = os.path.dirname(os.path.abspath(path))
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)

    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            fd = -1
            f.write(raw)
    finally:
        if fd != -1:
            os.close(fd)
    os.replace(tmp, path)


def load_tickets(path: str) -> Tuple[Optional[Dict[str, Any]], Optional[str], Optional[str]]:
    """Load ticket data from a binary ticket store.

    Returns (bundle_dict, client_id, service_id) on success. If Ticket_V has
    expired but TGT is still valid, the returned bundle keeps TGT material so the
    caller can skip AS and request a fresh Ticket_V from TGS.
    """
    if not path or not os.path.isfile(path):
        return None, None, None

    try:
        if os.path.getsize(path) > MAX_STORE_BYTES:
            return None, None, None
        with open(path, "rb") as f:
            raw = f.read()
    except OSError:
        return None, None, None

    try:
        offset = 0
        magic, offset = _read_exact(raw, offset, len(MAGIC))
        if magic != MAGIC:
            return None, None, None

        client_id_raw, offset = _read_u16_blob(raw, offset)
        service_id_raw, offset = _read_u16_blob(raw, offset)
        expires_raw, offset = _read_exact(raw, offset, 8)
        tgt_expire, tv_expire = struct.unpack(">II", expires_raw)
        key_c_tgs, offset = _read_u16_blob(raw, offset)
        ticket_tgs, offset = _read_u32_blob(raw, offset)
        key_c_v, offset = _read_u16_blob(raw, offset)
        ticket_v, offset = _read_u32_blob(raw, offset)

        if offset != len(raw):
            return None, None, None

        client_id = client_id_raw.decode("utf-8")
        service_id = service_id_raw.decode("utf-8")
    except Exception:
        return None, None, None

    now = int(time.time())
    has_tgt = bool(key_c_tgs and ticket_tgs and now < tgt_expire)
    has_ticket_v = bool(key_c_v and ticket_v and now < tv_expire)

    if not has_tgt and not has_ticket_v:
        if now >= tgt_expire and now >= tv_expire:
            delete_tickets(path)
        return None, None, None

    bundle = {
        "key_c_tgs": key_c_tgs if has_tgt else b"",
        "ticket_tgs": ticket_tgs if has_tgt else b"",
        "key_c_v": key_c_v if has_ticket_v else b"",
        "ticket_v": ticket_v if has_ticket_v else b"",
        "tgt_expire": tgt_expire,
        "tv_expire": tv_expire,
    }

    return bundle, client_id, service_id


def delete_tickets(path: str) -> None:
    """Remove the ticket file if it exists."""
    if path and os.path.isfile(path):
        try:
            os.remove(path)
        except OSError:
            pass
