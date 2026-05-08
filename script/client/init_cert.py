#!/usr/bin/env python3
"""Generate RSA private key and certificate for a CLIENT_N identity."""

from __future__ import annotations

import argparse
import json
import shutil
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


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def hex_int(value: int) -> str:
    return format(value, "x")


def write_json(path: Path, value: dict, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    path.chmod(mode)


def prompt_client_number() -> int:
    raw = input("CLIENT number: ").strip()
    return parse_client_number(raw)


def parse_client_number(raw: str) -> int:
    try:
        value = int(raw, 10)
    except ValueError as exc:
        raise SystemExit(f"Invalid client number: {raw}") from exc
    if value <= 0:
        raise SystemExit("Client number must be greater than 0.")
    return value


def generate_rsa_keypair() -> tuple[dict, dict, rsa.RSAPrivateKey]:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_numbers = priv.public_key().public_numbers()
    priv_numbers = priv.private_numbers()
    private_doc = {
        "n": hex_int(pub_numbers.n),
        "e": hex_int(pub_numbers.e).zfill(6),
        "d": hex_int(priv_numbers.d),
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
    return json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def create_certificate(entity_id: str, issuer: str, expire: str, public_doc: dict, priv: rsa.RSAPrivateKey) -> dict:
    body = cert_body(entity_id, issuer, public_doc, expire)
    signature = priv.sign(body_bytes(body), padding.PKCS1v15(), hashes.SHA256())
    body["sign"] = signature.hex()
    return body


def copy_alias(src: Path, dst: Path, mode: int) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dst)
    dst.chmod(mode)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate RSA private key and certificate for CLIENT_N.")
    parser.add_argument("number", nargs="?", help="client number. 1 generates CLIENT_1, 2 generates CLIENT_2, etc.")
    parser.add_argument("--root", type=Path, default=repo_root(), help="project root, default: repository root")
    parser.add_argument("--issuer", default=DEFAULT_ISSUER, help=f"issuer, default: {DEFAULT_ISSUER}")
    parser.add_argument("--expire", default=DEFAULT_EXPIRE, help=f"expire date YYYY-MM-DD, default: {DEFAULT_EXPIRE}")
    parser.add_argument(
        "--no-active-alias",
        action="store_true",
        help="do not update client/keys/client_priv.json and client/certs/cert_client.json",
    )
    parser.add_argument(
        "--write-public-json",
        action="store_true",
        help="also write client/keys/clientN_pub.json. Normally unnecessary because the certificate contains the public key.",
    )
    args = parser.parse_args()

    number = parse_client_number(args.number) if args.number is not None else prompt_client_number()
    client_id = f"CLIENT_{number}"
    root = args.root.resolve()

    private_doc, public_doc, priv = generate_rsa_keypair()
    cert = create_certificate(client_id, args.issuer, args.expire, public_doc, priv)

    client_key_dir = root / "client" / "keys"
    client_cert_dir = root / "client" / "certs"
    server_cert_dir = root / "certs"

    private_path = client_key_dir / f"client{number}_priv.json"
    client_cert_path = client_cert_dir / f"cert_client{number}.json"
    server_cert_path = server_cert_dir / f"client{number}_cert.json"

    write_json(private_path, private_doc, 0o600)
    write_json(client_cert_path, cert, 0o644)
    write_json(server_cert_path, cert, 0o644)

    print(f"Client id:           {client_id}")
    print(f"Client private key:  {private_path}")
    print(f"Client certificate:  {client_cert_path}")
    print(f"Server certificate:  {server_cert_path}")

    if args.write_public_json:
        public_path = client_key_dir / f"client{number}_pub.json"
        write_json(public_path, public_doc, 0o644)
        print(f"Client public key:   {public_path}")

    if not args.no_active_alias:
        active_priv = client_key_dir / "client_priv.json"
        active_cert = client_cert_dir / "cert_client.json"
        copy_alias(private_path, active_priv, 0o600)
        copy_alias(client_cert_path, active_cert, 0o644)
        print(f"Active private key:  {active_priv}")
        print(f"Active certificate:  {active_cert}")


if __name__ == "__main__":
    main()
