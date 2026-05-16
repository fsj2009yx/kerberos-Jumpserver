#!/usr/bin/env python3
"""Generate V and client RSA keys/certificates in one command."""

from __future__ import annotations

import argparse
import json
import shutil
from dataclasses import dataclass
from pathlib import Path

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
except ImportError as exc:  # pragma: no cover
    raise SystemExit(
        "Missing dependency: cryptography. Run with client/proxy/.venv/bin/python "
        "or install cryptography in your Python environment."
    ) from exc


DEFAULT_ISSUER = "LOCAL_DEBUG_CA"
DEFAULT_EXPIRE = "2036-12-31"
DEFAULT_CLIENT_COUNT = 4


@dataclass(frozen=True)
class GeneratedIdentity:
    entity_id: str
    private_doc: dict
    public_doc: dict
    certificate: dict


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def hex_int(value: int, width: int = 0) -> str:
    return format(value, "x").zfill(width)


def write_json(path: Path, value: dict, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    path.chmod(mode)


def copy_file(src: Path, dst: Path, mode: int) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dst)
    dst.chmod(mode)


def generate_rsa_keypair() -> tuple[dict, dict, rsa.RSAPrivateKey]:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_numbers = priv.public_key().public_numbers()
    priv_numbers = priv.private_numbers()
    private_doc = {
        "n": hex_int(pub_numbers.n, 512),
        "e": hex_int(pub_numbers.e).zfill(6),
        "d": hex_int(priv_numbers.d, 512),
    }
    public_doc = {
        "n": private_doc["n"],
        "e": private_doc["e"],
    }
    return private_doc, public_doc, priv


def cert_body(entity_id: str, issuer: str, public_doc: dict, expire: str) -> dict:
    return {
        "id": entity_id,
        "issuer": issuer,
        "public_key": {
            "n": public_doc["n"],
            "e": public_doc["e"],
        },
        "expire": expire,
    }


def body_bytes(body: dict) -> bytes:
    # Keep this byte-for-byte compatible with Go common/krb.CertBodyBytes.
    return json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def create_certificate(entity_id: str, issuer: str, expire: str, public_doc: dict, priv: rsa.RSAPrivateKey) -> dict:
    body = cert_body(entity_id, issuer, public_doc, expire)
    signature = priv.sign(body_bytes(body), padding.PKCS1v15(), hashes.SHA256())
    body["sign"] = signature.hex()
    return body


def generate_identity(entity_id: str, issuer: str, expire: str) -> GeneratedIdentity:
    private_doc, public_doc, priv = generate_rsa_keypair()
    cert = create_certificate(entity_id, issuer, expire, public_doc, priv)
    return GeneratedIdentity(entity_id, private_doc, public_doc, cert)


def parse_positive_int(raw: str, field: str) -> int:
    try:
        value = int(raw, 10)
    except ValueError as exc:
        raise SystemExit(f"{field} must be an integer: {raw}") from exc
    if value <= 0:
        raise SystemExit(f"{field} must be greater than 0.")
    return value


def client_ids(count: int) -> list[str]:
    return [f"CLIENT_{i}" for i in range(1, count + 1)]


def client_number(client_id: str) -> int:
    prefix = "CLIENT_"
    if not client_id.startswith(prefix):
        raise SystemExit(f"Unsupported client id format: {client_id}")
    return parse_positive_int(client_id[len(prefix):], "client number")


def write_v_identity(root: Path, issuer: str, expire: str, write_public: bool) -> None:
    identity = generate_identity("verify_server", issuer, expire)
    private_path = root / "keys" / "v_priv.json"
    cert_path = root / "certs" / "v_cert.json"

    write_json(private_path, identity.private_doc, 0o600)
    write_json(cert_path, identity.certificate, 0o644)
    print(f"{identity.entity_id:<14} private: {private_path}")
    print(f"{identity.entity_id:<14} cert:    {cert_path}")

    if write_public:
        public_path = root / "keys" / "v_pub.json"
        write_json(public_path, identity.public_doc, 0o644)
        print(f"{identity.entity_id:<14} public:  {public_path}")


def write_client_identity(root: Path, client_id: str, issuer: str, expire: str, write_public: bool) -> tuple[Path, Path]:
    number = client_number(client_id)
    identity = generate_identity(client_id, issuer, expire)

    private_path = root / "client" / "keys" / f"client{number}_priv.json"
    local_cert_path = root / "client" / "certs" / f"cert_client{number}.json"
    server_cert_path = root / "certs" / f"client{number}_cert.json"

    write_json(private_path, identity.private_doc, 0o600)
    write_json(local_cert_path, identity.certificate, 0o644)
    write_json(server_cert_path, identity.certificate, 0o644)

    print(f"{client_id:<14} private: {private_path}")
    print(f"{client_id:<14} cert:    {local_cert_path}")
    print(f"{client_id:<14} shared:  {server_cert_path}")

    if write_public:
        public_path = root / "client" / "keys" / f"client{number}_pub.json"
        write_json(public_path, identity.public_doc, 0o644)
        print(f"{client_id:<14} public:  {public_path}")

    return private_path, local_cert_path


def write_active_alias(root: Path, active_client: int, private_path: Path, cert_path: Path) -> None:
    active_private = root / "client" / "keys" / "client_priv.json"
    active_cert = root / "client" / "certs" / "cert_client.json"
    copy_file(private_path, active_private, 0o600)
    copy_file(cert_path, active_cert, 0o644)
    print(f"CLIENT_{active_client:<7} alias:   {active_private}")
    print(f"CLIENT_{active_client:<7} alias:   {active_cert}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate V and CLIENT_N RSA keys/certificates for this project."
    )
    parser.add_argument("--root", type=Path, default=repo_root(), help="project root, default: repository root")
    parser.add_argument("--issuer", default=DEFAULT_ISSUER, help=f"issuer, default: {DEFAULT_ISSUER}")
    parser.add_argument("--expire", default=DEFAULT_EXPIRE, help=f"expire date YYYY-MM-DD, default: {DEFAULT_EXPIRE}")
    parser.add_argument(
        "--clients",
        type=lambda raw: parse_positive_int(raw, "clients"),
        default=DEFAULT_CLIENT_COUNT,
        help=f"number of CLIENT_N identities to generate, default: {DEFAULT_CLIENT_COUNT}",
    )
    parser.add_argument(
        "--active-client",
        type=lambda raw: parse_positive_int(raw, "active-client"),
        default=1,
        help="CLIENT_N copied to client/keys/client_priv.json and client/certs/cert_client.json, default: 1",
    )
    parser.add_argument(
        "--no-active-alias",
        action="store_true",
        help="do not update client/keys/client_priv.json and client/certs/cert_client.json",
    )
    parser.add_argument(
        "--write-public-json",
        action="store_true",
        help="also write *_pub.json files for debugging. Normal runtime does not need them.",
    )
    args = parser.parse_args()

    if args.active_client > args.clients:
        raise SystemExit("--active-client must be less than or equal to --clients.")

    root = args.root.resolve()
    root.mkdir(parents=True, exist_ok=True)

    print(f"Project root: {root}")
    print(f"Issuer:       {args.issuer}")
    print(f"Expire:       {args.expire}")
    print("")

    print("Generating V identity...")
    write_v_identity(root, args.issuer, args.expire, args.write_public_json)

    print("\nGenerating client identities...")
    active_paths = None
    for client_id in client_ids(args.clients):
        private_path, cert_path = write_client_identity(root, client_id, args.issuer, args.expire, args.write_public_json)
        if client_number(client_id) == args.active_client:
            active_paths = (private_path, cert_path)

    if not args.no_active_alias and active_paths is not None:
        print("\nUpdating active client alias...")
        write_active_alias(root, args.active_client, active_paths[0], active_paths[1])

    print("\nDone. Generated only the V/Client certificate files required by the APP signature flow.")


if __name__ == "__main__":
    main()
