#!/usr/bin/env python3
"""Generate all certificates and keys for the Kerberos system."""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
except ImportError as exc:
    raise SystemExit(
        "Missing dependency: cryptography. Install with pip install cryptography"
    ) from exc


DEFAULT_ISSUER = "LOCAL_DEBUG_CA"
DEFAULT_EXPIRE = "2036-12-31"


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def hex_int(value: int) -> str:
    return format(value, "x")


def write_json(path: Path, value: dict, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


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


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate all certificates and keys for Kerberos system.")
    parser.add_argument("--root", type=Path, default=repo_root(), help="project root")
    args = parser.parse_args()

    root = args.root.resolve()
    issuer = DEFAULT_ISSUER
    expire = DEFAULT_EXPIRE

    print("Generating all certificates and keys...\n")

    # Generate AS server certificate and key
    print("1. Generating AS server certificate and key...")
    as_private_doc, as_public_doc, as_priv = generate_rsa_keypair()
    as_cert = create_certificate("AS", issuer, expire, as_public_doc, as_priv)
    
    as_key_dir = root / "as_server" / "keys"
    as_cert_dir = root / "as_server" / "certs"
    
    write_json(as_key_dir / "as_priv.json", as_private_doc)
    write_json(as_cert_dir / "as_cert.json", as_cert)
    print(f"   - AS private key: {as_key_dir / 'as_priv.json'}")
    print(f"   - AS certificate: {as_cert_dir / 'as_cert.json'}")

    # Generate TGS server certificate and key
    print("\n2. Generating TGS server certificate and key...")
    tgs_private_doc, tgs_public_doc, tgs_priv = generate_rsa_keypair()
    tgs_cert = create_certificate("TGS", issuer, expire, tgs_public_doc, tgs_priv)
    
    tgs_key_dir = root / "tgs_server" / "keys"
    tgs_cert_dir = root / "tgs_server" / "certs"
    
    write_json(tgs_key_dir / "tgs_priv.json", tgs_private_doc)
    write_json(tgs_cert_dir / "tgs_cert.json", tgs_cert)
    print(f"   - TGS private key: {tgs_key_dir / 'tgs_priv.json'}")
    print(f"   - TGS certificate: {tgs_cert_dir / 'tgs_cert.json'}")

    # Generate V server certificate and key
    print("\n3. Generating V server certificate and key...")
    v_private_doc, v_public_doc, v_priv = generate_rsa_keypair()
    v_cert = create_certificate("verify_server", issuer, expire, v_public_doc, v_priv)
    
    v_key_dir = root / "verify_server" / "keys"
    v_cert_dir = root / "verify_server" / "certs"
    
    write_json(v_key_dir / "v_priv.json", v_private_doc)
    write_json(v_cert_dir / "v_cert.json", v_cert)
    print(f"   - V private key: {v_key_dir / 'v_priv.json'}")
    print(f"   - V certificate: {v_cert_dir / 'v_cert.json'}")

    # Generate client certificates
    print("\n4. Generating client certificates...")
    for i in range(1, 5):
        client_id = f"CLIENT_{i}"
        client_private_doc, client_public_doc, client_priv = generate_rsa_keypair()
        client_cert = create_certificate(client_id, issuer, expire, client_public_doc, client_priv)
        
        # Client-side files
        client_key_dir = root / "client" / "keys"
        client_cert_dir = root / "client" / "certs"
        
        # Server-side files (for verification)
        server_cert_dir = root / "certs"
        
        write_json(client_key_dir / f"client{i}_priv.json", client_private_doc)
        write_json(client_cert_dir / f"cert_client{i}.json", client_cert)
        write_json(server_cert_dir / f"client{i}_cert.json", client_cert)
        
        # Copy to server-specific directories
        shutil.copy(server_cert_dir / f"client{i}_cert.json", as_cert_dir / f"client{i}_cert.json")
        shutil.copy(server_cert_dir / f"client{i}_cert.json", tgs_cert_dir / f"client{i}_cert.json")
        shutil.copy(server_cert_dir / f"client{i}_cert.json", v_cert_dir / f"client{i}_cert.json")
        
        print(f"   - {client_id}: {client_cert_dir / f'cert_client{i}.json'}")

        # Update active client aliases for CLIENT_1
        if i == 1:
            shutil.copy(client_key_dir / f"client{i}_priv.json", client_key_dir / "client_priv.json")
            shutil.copy(client_cert_dir / f"cert_client{i}.json", client_cert_dir / "cert_client.json")
            print(f"     * Set as active client")

    print("\n✅ All certificates and keys generated successfully!")


if __name__ == "__main__":
    main()
