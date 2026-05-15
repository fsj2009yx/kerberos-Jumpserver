"""Ticket persistence — save/load Kerberos tickets to local JSON storage."""

import base64
import json
import os
import time
from typing import Any, Dict, Optional, Tuple


def save_tickets(bundle: Any, client_id: str, service_id: str, path: str) -> None:
    """Serialize TicketBundle to a JSON file with base64-encoded binary fields."""
    if not path:
        return

    data: Dict[str, Any] = {
        "client_id": client_id,
        "service_id": service_id,
        "key_c_tgs": base64.b64encode(bundle.key_c_tgs).decode("ascii") if bundle.key_c_tgs else "",
        "ticket_tgs": base64.b64encode(bundle.ticket_tgs).decode("ascii") if bundle.ticket_tgs else "",
        "key_c_v": base64.b64encode(bundle.key_c_v).decode("ascii") if bundle.key_c_v else "",
        "ticket_v": base64.b64encode(bundle.ticket_v).decode("ascii") if bundle.ticket_v else "",
        "tgt_expire": bundle.tgt_expire,
        "tv_expire": bundle.tv_expire,
        "saved_at": int(time.time()),
    }

    parent = os.path.dirname(os.path.abspath(path))
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)

    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)


def load_tickets(path: str) -> Tuple[Optional[Dict[str, Any]], Optional[str], Optional[str]]:
    """Load ticket data from a JSON file.

    Returns (bundle_dict, client_id, service_id) on success, or (None, None, None)
    if the file is missing, malformed, or the tickets have expired.
    """
    if not path or not os.path.isfile(path):
        return None, None, None

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, IOError):
        return None, None, None

    required = ("client_id", "service_id", "key_c_tgs", "ticket_tgs",
                "key_c_v", "ticket_v", "tgt_expire", "tv_expire")
    if not all(k in data for k in required):
        return None, None, None

    now = int(time.time())
    tv_expire = int(data["tv_expire"])
    tgt_expire = int(data["tgt_expire"])

    if now >= tv_expire:
        delete_tickets(path)
        return None, None, None

    # Decode base64 fields
    try:
        bundle = {
            "key_c_tgs": base64.b64decode(data["key_c_tgs"]) if data["key_c_tgs"] else b"",
            "ticket_tgs": base64.b64decode(data["ticket_tgs"]) if data["ticket_tgs"] else b"",
            "key_c_v": base64.b64decode(data["key_c_v"]) if data["key_c_v"] else b"",
            "ticket_v": base64.b64decode(data["ticket_v"]) if data["ticket_v"] else b"",
            "tgt_expire": tgt_expire,
            "tv_expire": tv_expire,
        }
    except Exception:
        return None, None, None

    if not bundle["key_c_v"] or not bundle["ticket_v"]:
        return None, None, None

    return bundle, data["client_id"], data["service_id"]


def delete_tickets(path: str) -> None:
    """Remove the ticket file if it exists."""
    if path and os.path.isfile(path):
        try:
            os.remove(path)
        except OSError:
            pass
