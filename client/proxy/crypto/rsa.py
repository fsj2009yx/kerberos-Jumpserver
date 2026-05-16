"""RSA-2048签名实现"""

# PKCS#1 v1.5 编码前缀（SHA-256）
PKCS1_PREFIX = bytes([
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
])


def extended_gcd(a, b):
    """扩展欧几里得算法"""
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y


def mod_inverse(e, phi_n):
    """计算模逆"""
    gcd, x, _ = extended_gcd(e % phi_n, phi_n)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist")
    return (x % phi_n + phi_n) % phi_n


def pow_mod(base, exp, mod):
    """快速模幂运算"""
    result = 1
    base = base % mod
    while exp > 0:
        if exp & 1:
            result = (result * base) % mod
        exp = exp >> 1
        base = (base * base) % mod
    return result


def bytes_to_int(data):
    """字节串转大整数（大端序）"""
    result = 0
    for byte in data:
        result = (result << 8) | byte
    return result


def hex_to_int(value, field_name):
    """Convert project RSA hex fields to int, accepting older odd-length keys."""
    if not isinstance(value, str):
        raise ValueError(f"RSA {field_name} must be a hex string")

    value = value.strip()
    if not value:
        raise ValueError(f"RSA {field_name} is empty")
    if len(value) % 2 == 1:
        value = "0" + value

    try:
        return bytes_to_int(bytes.fromhex(value))
    except ValueError as exc:
        raise ValueError(f"RSA {field_name} contains non-hex characters") from exc


def int_to_bytes(value, length=256):
    """大整数转字节串（大端序）"""
    result = bytearray()
    for i in range(length - 1, -1, -1):
        result.append((value >> (i * 8)) & 0xFF)
    return bytes(result)


def pkcs1_v15_encode(msg_hash):
    """PKCS#1 v1.5编码（用于签名）"""
    if len(msg_hash) != 32:
        raise ValueError("SHA-256 hash must be 32 bytes")
    
    # EM = 0x00 || 0x01 || PS || 0x00 || DigestInfo || Hash
    # PS: 全0xFF填充，长度 = 256 - 3 - 19 - 32 = 202字节
    ps = bytes([0xFF] * 202)
    em = b'\x00\x01' + ps + b'\x00' + PKCS1_PREFIX + msg_hash
    
    if len(em) != 256:
        raise ValueError("PKCS#1 encoding error")
    
    return em


def rsa_sign(msg_hash, priv_key):
    """RSA签名"""
    # PKCS#1 v1.5编码
    em = pkcs1_v15_encode(msg_hash)
    
    # 转换为大整数
    m = bytes_to_int(em)
    
    # 签名: s = m^d mod n
    n = hex_to_int(priv_key['n'], "n")
    d = hex_to_int(priv_key['d'], "d")
    
    s = pow_mod(m, d, n)
    
    # 转换为256字节（大端序）
    signature = int_to_bytes(s)
    
    return signature


def rsa_verify(msg_hash, signature, pub_key):
    """RSA验签"""
    if len(msg_hash) != 32:
        raise ValueError("SHA-256 hash must be 32 bytes")
    
    if len(signature) != 256:
        raise ValueError("Signature must be 256 bytes")
    
    # 转换为大整数
    s = bytes_to_int(signature)
    
    # 验签: m' = s^e mod n
    n = hex_to_int(pub_key['n'], "n")
    e = hex_to_int(pub_key['e'], "e")
    
    m_prime = pow_mod(s, e, n)
    
    # 转换为字节串
    em_prime = int_to_bytes(m_prime)
    
    # 验证编码格式
    if em_prime[0] != 0x00 or em_prime[1] != 0x01:
        return False
    
    # 找到0x00分隔符
    separator_pos = 2
    while separator_pos < len(em_prime) and em_prime[separator_pos] == 0xFF:
        separator_pos += 1
    
    if separator_pos >= len(em_prime) or em_prime[separator_pos] != 0x00:
        return False
    
    # 验证DigestInfo前缀
    digest_info_pos = separator_pos + 1
    if em_prime[digest_info_pos:digest_info_pos+19] != PKCS1_PREFIX:
        return False
    
    # 验证哈希值
    hash_pos = digest_info_pos + 19
    recovered_hash = em_prime[hash_pos:hash_pos+32]
    
    return recovered_hash == msg_hash
