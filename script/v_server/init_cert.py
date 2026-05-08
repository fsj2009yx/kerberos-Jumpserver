#!/usr/bin/env python3
"""Generate RSA private key and certificate for the V server."""

from __future__ import annotations

import argparse
import json
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
    # Match Go encoding/json output from common/krb.CertBodyBytes.
    return json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def create_certificate(entity_id: str, issuer: str, expire: str, public_doc: dict, priv: rsa.RSAPrivateKey) -> dict:
    body = cert_body(entity_id, issuer, public_doc, expire)
    signature = priv.sign(body_bytes(body), padding.PKCS1v15(), hashes.SHA256())
    body["sign"] = signature.hex()
    return body


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate V server RSA private key and certificate.")
    parser.add_argument("--root", type=Path, default=repo_root(), help="project root, default: repository root")
    parser.add_argument("--id", default="verify_server", help="certificate id, default: verify_server")
    parser.add_argument("--issuer", default=DEFAULT_ISSUER, help=f"issuer, default: {DEFAULT_ISSUER}")
    parser.add_argument("--expire", default=DEFAULT_EXPIRE, help=f"expire date YYYY-MM-DD, default: {DEFAULT_EXPIRE}")
    parser.add_argument(
        "--write-public-json",
        action="store_true",
        help="also write keys/v_pub.json. Normally unnecessary because certs/v_cert.json contains the public key.",
    )
    args = parser.parse_args()

    root = args.root.resolve()
    private_doc, public_doc, priv = generate_rsa_keypair()
    cert = create_certificate(args.id, args.issuer, args.expire, public_doc, priv)

    priv_path = root / "keys" / "v_priv.json"
    cert_path = root / "certs" / "v_cert.json"

    write_json(priv_path, private_doc, 0o600)
    write_json(cert_path, cert, 0o644)

    print(f"V private key: {priv_path}")
    print(f"V certificate: {cert_path}")
    print(f"V cert id:     {args.id}")
    if args.write_public_json:
        pub_path = root / "keys" / "v_pub.json"
        write_json(pub_path, public_doc, 0o644)
        print(f"V public key:  {pub_path}")


if __name__ == "__main__":
    main()
