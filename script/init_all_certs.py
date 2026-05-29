#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""一键生成 V 和客户端 RSA 密钥/证书。

init_all_certs.go 的自包含 Python 重写版本——实现 RSA 密钥生成、
Miller-Rabin 素性测试和 PKCS#1 v1.5 证书签名，仅依赖 Python 标准库。
"""

from __future__ import annotations   # 允许在类型注解中使用类自身的引用

import argparse                     # 命令行参数解析
import hashlib                      # SHA‑256 哈希
import json                         # 读写 JSON 证书和密钥
import secrets                      # 密码学安全的随机数（从系统熵源）
import shutil                       # 文件复制，用于创建活动别名
from pathlib import Path            # 面向对象的路径操作

# ---------- 默认配置 ----------
DEFAULT_ISSUER = "LOCAL_DEBUG_CA"   # 证书的签发者字段
DEFAULT_EXPIRE = "2036-12-31"       # 证书有效期，格式 YYYY-MM-DD
DEFAULT_CLIENT_COUNT = 4            # 默认生成 4 个客户端身份
RSA_BITS = 2048                     # RSA 模数位数
RSA_PUBLIC_EXPONENT = 65537         # 公钥指数 e（0x010001）

# PKCS#1 v1.5 中 SHA‑256 的 DigestInfo 前缀（19 字节）
SHA256_DIGEST_INFO_PREFIX = bytes([
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
])

# 小素数表，用于快速试除，提高素性测试效率
SMALL_PRIMES = [
    2, 3, 5, 7, 11, 13, 17, 19, 23,
    29, 31, 37, 41, 43, 47, 53, 59, 61,
    67, 71, 73, 79, 83, 89, 97,
]


def _hex_int(value: int, width: int = 0) -> str:
    """将整数转换为十六进制字符串，可选左补零到指定宽度。"""
    return format(value, "x").zfill(width)


def _quick_pow(base: int, exp: int, mod: int) -> int:
    """快速模幂运算 —— 从右到左的二进制平方‑乘算法。"""
    result = 1
    base_mod = base % mod
    e = exp
    while e > 0:
        if e & 1:                     # 若当前最低位为 1
            result = (result * base_mod) % mod
        base_mod = (base_mod * base_mod) % mod   # 平方
        e >>= 1                       # 右移一位
    return result


def _exgcd(a: int, b: int) -> tuple[int, int, int]:
    """扩展欧几里得算法，返回 (gcd, x, y) 满足 a*x + b*y = gcd。"""
    if b == 0:
        return a, 1, 0
    d, x, y = _exgcd(b, a % b)
    # 回溯：x = y_old, y = x_old - (a//b) * y_old
    return d, y, x - (a // b) * y


def _mod_inverse(a: int, m: int) -> int:
    """计算 a 模 m 的乘法逆元，若不存在则返回 -1。"""
    g, x, _ = _exgcd(a % m, m)
    if g != 1:
        return -1                    # 无逆元
    return x % m                     # 确保结果为正


def _generate_random_big_int(bits: int) -> int:
    """生成恰好 `bits` 位的随机大整数，且保证最低位为 1（奇数）。"""
    if bits < 2:
        raise ValueError("random integer bit length must be at least 2")

    out = 0
    full_words = bits // 64           # 每次生成 64 位（8 字节）随机数
    for _ in range(full_words):
        buf = secrets.token_bytes(8)  # 64 位安全随机数
        out = (out << 64) | int.from_bytes(buf, "big")

    remaining_bits = bits % 64
    if remaining_bits > 0:
        buf = secrets.token_bytes(8)
        # 截取低 remaining_bits 位
        value = int.from_bytes(buf, "big") & ((1 << remaining_bits) - 1)
        out = (out << remaining_bits) | value

    out |= (1 << (bits - 1))          # 确保最高位为 1（恰好 bits 位）
    out |= 1                          # 确保最低位为 1（奇数）
    return out


def _miller_rabin(n: int, test_time: int) -> bool:
    """Miller‑Rabin 素性测试，test_time 为随机底数测试轮数。"""
    if n < 3 or n % 2 == 0:
        return n == 2
    if n % 3 == 0:
        return n == 3

    # 将 n-1 写成 u * 2^t 的形式，u 为奇数
    u = n - 1
    t = 0
    while u % 2 == 0:
        u //= 2
        t += 1

    n_minus_3 = n - 3
    for _ in range(test_time):
        # 随机选取底数 a ∈ [2, n-2]
        a = _generate_random_big_int(n.bit_length())
        a = a % n_minus_3 + 2

        v = _quick_pow(a, u, n)
        if v == 1 or v == n - 1:
            continue

        s = 0
        while s < t:
            v = (v * v) % n
            if v == n - 1:
                break
            s += 1

        if s == t:                     # 从未遇到 -1，说明 n 是合数
            return False

    return True                        # 通过所有轮测试，极可能为素数


def _is_prime(n: int) -> bool:
    """先用小素数试除，再调用 Miller‑Rabin（8 轮）。"""
    if n < 2:
        return False
    for p in SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    return _miller_rabin(n, 8)          # 8 轮错误概率 < 4⁻⁸ ≈ 1.5e‑5


def _generate_prime_by_search(bits: int) -> int:
    """生成恰好 `bits` 位的素数。从随机奇数开始，每次加 2 搜索。"""
    p = _generate_random_big_int(bits)
    while not _is_prime(p):
        p += 2
        if p.bit_length() != bits:      # 若进位导致位长增加，重新开始
            return _generate_prime_by_search(bits)
    return p


def _generate_rsa_keypair() -> tuple[dict, dict, dict]:
    """
    生成 RSA‑2048 密钥对。
    返回 (私钥文档, 公钥文档, 私钥整数结构)。
    私钥文档和公钥文档的格式与设计文档完全一致：
        {"n": hex_str, "e": hex_str, "d": hex_str}  # 私钥
        {"n": hex_str, "e": hex_str}                 # 公钥
    """
    e_val = RSA_PUBLIC_EXPONENT
    while True:
        p = _generate_prime_by_search(RSA_BITS // 2)   # 1024 位素数
        q = _generate_prime_by_search(RSA_BITS // 2)
        if p == q:
            continue                                   # 避免 p = q

        n = p * q
        if n.bit_length() != RSA_BITS:                 # 确保 n 正好是 2048 位
            continue
        #计算欧拉函数生成密钥d
        phi = (p - 1) * (q - 1)
        d = _mod_inverse(e_val, phi)
        if d <= 0:
            continue

        # 私钥文档：n、e、d 均为十六进制字符串，n 和 d 填到 512 个十六进制字符（256 字节）
        private_doc = {
            "n": _hex_int(n, 512),
            "e": _hex_int(e_val, 6),
            "d": _hex_int(d, 512),
        }
        public_doc = {
            "n": private_doc["n"],
            "e": private_doc["e"],
        }
        # 返回整数形式的私钥结构（用于后续签名运算）
        int_priv = {"n": n, "e": e_val, "d": d}
        return private_doc, public_doc, int_priv


def _emsa_pkcs1v15_encode(hash_bytes: bytes, size: int) -> bytes:
    """
    PKCS#1 v1.5 EMSA 编码，用于 SHA‑256。
    size = 256（RSA‑2048 的字节长度）。
    返回 EM（Encoded Message）长度为 size 的字节串。
    """
    if len(hash_bytes) != 32:
        raise ValueError("SHA-256 digest must be 32 bytes")

    t_len = len(SHA256_DIGEST_INFO_PREFIX) + len(hash_bytes)   # 19 + 32 = 51
    if size < t_len + 11:                                      # 最小需要 51+11=62
        raise ValueError("intended encoded message length too short")

    out = bytearray(size)
    out[0] = 0x00
    out[1] = 0x01
    ps_len = size - t_len - 3                                   # 256 - 51 - 3 = 202
    for i in range(2, 2 + ps_len):
        out[i] = 0xFF                                           # 填充 0xFF
    out[2 + ps_len] = 0x00                                      # 分隔符
    # 复制 DigestInfo 前缀
    start = 3 + ps_len
    out[start:start + len(SHA256_DIGEST_INFO_PREFIX)] = SHA256_DIGEST_INFO_PREFIX
    # 复制哈希值
    out[start + len(SHA256_DIGEST_INFO_PREFIX):] = hash_bytes
    return bytes(out)


def _rsa_sign_sha256_pkcs1v15(message: bytes, priv_key: dict) -> bytes:
    """
    使用 RSA 私钥对消息进行 PKCS#1 v1.5 签名（SHA‑256 哈希）。
    priv_key 是整数型字典，包含 "n", "e", "d"。
    返回 256 字节签名。
    """
    digest = hashlib.sha256(message).digest()
    em = _emsa_pkcs1v15_encode(digest, RSA_BITS // 8)           # EM 长 256 字节
    m = int.from_bytes(em, "big")                               # 转为大整数
    s = _quick_pow(m, priv_key["d"], priv_key["n"])             # s = m^d mod n
    return s.to_bytes(RSA_BITS // 8, "big")                     # 转为 256 字节大端


def _body_bytes(body: dict) -> bytes:
    """将证书主体（不含 sign 字段）规范化为字节串，用于签名和验签。"""
    # separators=(",",":") 去除不必要的空格，确保签名可重现
    # ensure_ascii=False 保留 UTF‑8 字符（id 可能含中文，但本项目只用 ASCII）
    return json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _create_certificate(entity_id: str, issuer: str, expire: str,
                        public_doc: dict, priv_key: dict) -> dict:
    """
    创建自签名证书。
    entity_id: 证书持有者标识（如 "CLIENT_1" 或 "verify_server"）
    issuer:    签发者（固定为 LOCAL_DEBUG_CA）
    expire:    有效期（YYYY-MM-DD）
    public_doc: 公钥文档（{"n":..., "e":...}）
    priv_key:   整数型私钥字典
    返回完整证书 JSON（含 sign 字段）。
    """
    body = {
        "id": entity_id,
        "issuer": issuer,
        "public_key": {"n": public_doc["n"], "e": public_doc["e"]},
        "expire": expire,
    }
    # 对主体字节进行签名
    signature = _rsa_sign_sha256_pkcs1v15(_body_bytes(body), priv_key)
    body["sign"] = signature.hex()
    return body


def _generate_identity(entity_id: str, issuer: str, expire: str) -> tuple[dict, dict, dict]:
    """生成一整套身份：私钥文档、公钥文档、证书。"""
    private_doc, public_doc, priv_key = _generate_rsa_keypair()
    cert = _create_certificate(entity_id, issuer, expire, public_doc, priv_key)
    return private_doc, public_doc, cert


def _repo_root() -> Path:
    """返回项目的根目录（当前脚本的父目录的父目录）。"""
    return Path(__file__).resolve().parents[1]


def _parse_positive_int(raw: str, field: str) -> int:
    """解析正整数字符串，否则退出。"""
    try:
        value = int(raw.strip(), 10)
    except ValueError:
        raise SystemExit(f"{field} must be an integer: {raw}")
    if value <= 0:
        raise SystemExit(f"{field} must be greater than 0")
    return value


def _client_id(number: int) -> str:
    """根据数字生成客户端 ID，如 1 -> "CLIENT_1"。 """
    return f"CLIENT_{number}"


def _client_number(client_id: str) -> int:
    """从客户端 ID 中提取数字，例如 "CLIENT_1" -> 1。"""
    prefix = "CLIENT_"
    if not client_id.startswith(prefix):
        raise SystemExit(f"Unsupported client id format: {client_id}")
    return _parse_positive_int(client_id[len(prefix):], "client number")


def _write_json(path: Path, value: dict, mode: int) -> None:
    """将字典写入 JSON 文件，并设置文件权限模式（如 0o600）。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    path.chmod(mode)


def _copy_file(src: Path, dst: Path, mode: int) -> None:
    """复制文件并设置权限。"""
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dst)
    dst.chmod(mode)


def _write_v_identity(root: Path, issuer: str, expire: str, write_public: bool) -> None:
    """生成并保存 V 服务器的私钥、证书，可选保存公钥。"""
    private_doc, public_doc, cert = _generate_identity("verify_server", issuer, expire)

    private_path = root / "keys" / "v_priv.json"
    cert_path = root / "certs" / "v_cert.json"

    _write_json(private_path, private_doc, 0o600)
    _write_json(cert_path, cert, 0o644)
    print(f"{'verify_server':<14} private: {private_path}")
    print(f"{'verify_server':<14} cert:    {cert_path}")

    if write_public:
        public_path = root / "keys" / "v_pub.json"
        _write_json(public_path, public_doc, 0o644)
        print(f"{'verify_server':<14} public:  {public_path}")


def _write_client_identity(root: Path, client_id: str, issuer: str, expire: str,
                           write_public: bool) -> tuple[Path, Path]:
    """
    生成并保存单个客户端的私钥、证书。
    返回 (私钥路径, 证书路径)，用于后续创建活动别名。
    """
    number = _client_number(client_id)
    private_doc, public_doc, cert = _generate_identity(client_id, issuer, expire)

    private_path = root / "client" / "keys" / f"client{number}_priv.json"
    local_cert_path = root / "client" / "certs" / f"cert_client{number}.json"
    server_cert_path = root / "certs" / f"client{number}_cert.json"

    _write_json(private_path, private_doc, 0o600)
    _write_json(local_cert_path, cert, 0o644)
    _write_json(server_cert_path, cert, 0o644)

    print(f"{client_id:<14} private: {private_path}")
    print(f"{client_id:<14} cert:    {local_cert_path}")
    print(f"{client_id:<14} shared:  {server_cert_path}")

    if write_public:
        public_path = root / "client" / "keys" / f"client{number}_pub.json"
        _write_json(public_path, public_doc, 0o644)
        print(f"{client_id:<14} public:  {public_path}")

    return private_path, local_cert_path


def _write_active_alias(root: Path, active_client: int,
                        private_path: Path, cert_path: Path) -> None:
    """
    将指定的客户端材料复制为活动别名，供 Python proxy 直接使用。
    活动私钥: client/keys/client_priv.json
    活动证书: client/certs/cert_client.json
    """
    active_private = root / "client" / "keys" / "client_priv.json"
    active_cert = root / "client" / "certs" / "cert_client.json"
    _copy_file(private_path, active_private, 0o600)
    _copy_file(cert_path, active_cert, 0o644)
    print(f"CLIENT_{active_client:<7} alias:   {active_private}")
    print(f"CLIENT_{active_client:<7} alias:   {active_cert}")

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate V and CLIENT_N RSA keys/certificates for this project."
    )
    parser.add_argument(
        "--root", type=Path, default=_repo_root(),
        help="project root, default: repository root",
    )
    parser.add_argument(
        "--issuer", default=DEFAULT_ISSUER,
        help=f"issuer, default: {DEFAULT_ISSUER}",
    )
    parser.add_argument(
        "--expire", default=DEFAULT_EXPIRE,
        help=f"expire date YYYY-MM-DD, default: {DEFAULT_EXPIRE}",
    )
    parser.add_argument(
        "--clients",
        type=lambda raw: _parse_positive_int(raw, "clients"),
        default=DEFAULT_CLIENT_COUNT,
        help=f"number of CLIENT_N identities to generate, default: {DEFAULT_CLIENT_COUNT}",
    )
    parser.add_argument(
        "--active-client",
        type=lambda raw: _parse_positive_int(raw, "active-client"),
        default=1,
        help="CLIENT_N copied to client/keys/client_priv.json and "
             "client/certs/cert_client.json, default: 1",
    )
    parser.add_argument(
        "--no-active-alias",
        action="store_true",
        help="do not update client/keys/client_priv.json and "
             "client/certs/cert_client.json",
    )
    parser.add_argument(
        "--write-public-json",
        action="store_true",
        help="also write *_pub.json files for debugging",
    )
    args = parser.parse_args()

    if args.active_client > args.clients:
        raise SystemExit("--active-client must be less than or equal to --clients")

    root = args.root.resolve()
    root.mkdir(parents=True, exist_ok=True)

    print(f"Project root: {root}")
    print(f"Issuer:       {args.issuer}")
    print(f"Expire:       {args.expire}\n")

    print("Generating V identity...")
    _write_v_identity(root, args.issuer, args.expire, args.write_public_json)

    print("\nGenerating client identities...")
    active_private_path: Path | None = None
    active_cert_path: Path | None = None
    for i in range(1, args.clients + 1):
        private_path, cert_path = _write_client_identity(
            root, _client_id(i), args.issuer, args.expire, args.write_public_json,
        )
        if i == args.active_client:
            active_private_path = private_path
            active_cert_path = cert_path

    if not args.no_active_alias and active_private_path is not None:
        print("\nUpdating active client alias...")
        _write_active_alias(root, args.active_client, active_private_path, active_cert_path)

    print("\nDone. Generated only the V/Client certificate files required by the APP signature flow.")


if __name__ == "__main__":
    main()