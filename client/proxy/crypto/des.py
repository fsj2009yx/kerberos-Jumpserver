   """DES-CBC的加密实现"""

# 导入调试模块
try:
    from debug.debug import log_debug, log_encryption, log_decryption, hexdump
except ImportError:
    def log_debug(*args, **kwargs): pass
    def log_encryption(*args, **kwargs): pass
    def log_decryption(*args, **kwargs): pass
    def hexdump(*args, **kwargs): pass

# S-boxes for DES
S_BOXES = [
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
]

# Initial permutation table
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

# Final permutation table (inverse of IP)
FP = [40, 8, 48, 16, 56, 24, 64, 32,
      39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30,
      37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28,
      35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26,
      33, 1, 41, 9, 49, 17, 57, 25]

# Expansion table (32 bits to 48 bits)
E = [32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

# Permutation function P table
P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]

# PC-1 table (64 bits to 56 bits)
PC1 = [57, 49, 41, 33, 25, 17, 9,
       1, 58, 50, 42, 34, 26, 18,
       10, 2, 59, 51, 43, 35, 27,
       19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15,
       7, 62, 54, 46, 38, 30, 22,
       14, 6, 61, 53, 45, 37, 29,
       21, 13, 5, 28, 20, 12, 4]

# PC-2 table (56 bits to 48 bits)
PC2 = [14, 17, 11, 24, 1, 5, 3, 28,
       15, 6, 21, 10, 23, 19, 12, 4,
       26, 8, 16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55, 30, 40,
       51, 45, 33, 48, 44, 49, 39, 56,
       34, 53, 46, 42, 50, 36, 29, 32]

# Key shift schedule (number of shifts per round)
KEY_SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]


def permute_bits(data, input_bits, table):
    """执行DES置换，输出为紧凑的低位整数。"""
    result = 0
    for pos in table:
        bit = (data >> (input_bits - pos)) & 1
        result = (result << 1) | bit
    return result


def left_rotate_28(value, shifts):
    """28位左旋转"""
    return ((value << shifts) & 0xFFFFFFF) | (value >> (28 - shifts))


def generate_subkeys(key_64):
    """生成16个子密钥"""
    subkeys = []
    
    # PC-1置换：64位 -> 56位
    key_56 = permute_bits(key_64, 64, PC1)
    
    # 分成左右两部分各28位
    c = (key_56 >> 28) & 0xFFFFFFF
    d = key_56 & 0xFFFFFFF
    
    # 生成16个子密钥
    for shift in KEY_SHIFTS:
        c = left_rotate_28(c, shift)
        d = left_rotate_28(d, shift)
        
        # 合并并PC-2置换：56位 -> 48位
        cd = (c << 28) | d
        subkey = permute_bits(cd, 56, PC2)
        subkeys.append(subkey)
    
    return subkeys


def s_box_substitution(value_48):
    """S-box替换：48位 -> 32位"""
    result = 0
    for i in range(8):
        # 每个S-box处理6位
        s_input = (value_48 >> (42 - i * 6)) & 0x3F
        row = ((s_input >> 5) << 1) | (s_input & 1)
        col = (s_input >> 1) & 0x0F
        s_output = S_BOXES[i][row][col]
        result |= (s_output << (28 - i * 4))
    return result


def feistel_round(right_32, subkey_48):
    """单轮Feistel变换"""
    # E扩展：32位 -> 48位
    expanded = permute_bits(right_32, 32, E)
    
    # 与子密钥异或
    xor_result = expanded ^ subkey_48
    
    # S-box替换
    substituted = s_box_substitution(xor_result)
    
    # P置换
    return permute_bits(substituted, 32, P)


def des_encrypt_block(block_64, subkeys):
    """加密单个64位块"""
    # 初始置换IP
    block = permute_bits(block_64, 64, IP)
    
    # 分成左右两部分各32位
    left = (block >> 32) & 0xFFFFFFFF
    right = block & 0xFFFFFFFF
    
    # 16轮Feistel变换
    for i in range(16):
        temp = right
        right = left ^ feistel_round(right, subkeys[i])
        left = temp
    
    # 交换左右并最终置换FP
    combined = (right << 32) | left
    cipher = permute_bits(combined, 64, FP)
    
    return cipher


def des_decrypt_block(block_64, subkeys):
    """解密单个64位块"""
    # 初始置换IP
    block = permute_bits(block_64, 64, IP)
    
    # 分成左右两部分各32位
    left = (block >> 32) & 0xFFFFFFFF
    right = block & 0xFFFFFFFF
    
    # 逆序16轮Feistel变换
    for i in range(15, -1, -1):
        temp = right
        right = left ^ feistel_round(right, subkeys[i])
        left = temp
    
    # 交换左右并最终置换FP
    combined = (right << 32) | left
    plain = permute_bits(combined, 64, FP)
    
    return plain


def bytes_to_uint64(data):
    """8字节转64位整数（大端序）"""
    result = 0
    for i in range(8):
        result = (result << 8) | data[i]
    return result


def uint64_to_bytes(value):
    """64位整数转8字节（大端序）"""
    return bytes([(value >> (56 - i * 8)) & 0xFF for i in range(8)])


def pkcs7_pad(data, block_size=8):
    """PKCS7填充"""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data):
    """PKCS7去填充"""
    if len(data) == 0:
        return data
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 8:
        raise ValueError("Invalid PKCS7 padding")
    return data[:-pad_len]


def encrypt_des_cbc(key, plaintext, iv=None):
    """DES-CBC加密"""
    log_debug("=" * 50)
    log_debug("DES-CBC Encryption")
    log_debug(f"Key: {key.hex()}")
    log_debug(f"Plaintext length: {len(plaintext)} bytes")
    
    # 确保密钥是8字节
    if len(key) != 8:
        log_error(f"DES key must be 8 bytes, got {len(key)}")
        raise ValueError("DES key must be 8 bytes")
    
    # 生成子密钥
    key_64 = bytes_to_uint64(key)
    subkeys = generate_subkeys(key_64)
    log_debug(f"Generated {len(subkeys)} subkeys")
    
    # 生成随机IV
    if iv is None:
        iv = bytes([(i * 137) % 256 for i in range(8)])  # 简单的伪随机
    log_debug(f"IV: {iv.hex()}")
    
    iv_block = bytes_to_uint64(iv)
    
    # PKCS7填充
    padded = pkcs7_pad(plaintext)
    log_debug(f"After PKCS7 padding: {len(padded)} bytes")
    hexdump(plaintext, "Plaintext:")
    
    # CBC模式加密
    ciphertext = bytearray(iv)  # IV前置
    prev_block = iv_block
    
    for i in range(0, len(padded), 8):
        block = padded[i:i+8]
        block_64 = bytes_to_uint64(block)
        
        # 与前一个密文块异或
        xor_block = block_64 ^ prev_block
        
        # 加密
        encrypted = des_encrypt_block(xor_block, subkeys)
        
        # 保存密文
        ciphertext.extend(uint64_to_bytes(encrypted))
        prev_block = encrypted
    
    log_debug(f"Ciphertext length: {len(ciphertext)} bytes")
    hexdump(bytes(ciphertext), "Ciphertext:")
    log_debug("=" * 50)
    
    return bytes(ciphertext)


def decrypt_des_cbc(key, ciphertext):
    """DES-CBC解密"""
    log_debug("=" * 50)
    log_debug("DES-CBC Decryption")
    log_debug(f"Key: {key.hex()}")
    log_debug(f"Ciphertext length: {len(ciphertext)} bytes")
    hexdump(ciphertext, "Ciphertext:")
    
    # 确保密钥是8字节
    if len(key) != 8:
        log_error(f"DES key must be 8 bytes, got {len(key)}")
        raise ValueError("DES key must be 8 bytes")
    
    # 确保密文长度至少包含IV
    if len(ciphertext) < 8:
        log_error(f"Ciphertext too short: {len(ciphertext)} bytes")
        raise ValueError("Ciphertext too short")
    
    # 生成子密钥
    key_64 = bytes_to_uint64(key)
    subkeys = generate_subkeys(key_64)
    log_debug(f"Generated {len(subkeys)} subkeys")
    
    # 提取IV
    iv = ciphertext[:8]
    iv_block = bytes_to_uint64(iv)
    cipher_data = ciphertext[8:]
    log_debug(f"IV: {iv.hex()}")
    log_debug(f"Cipher data length: {len(cipher_data)} bytes")
    
    # 确保密文数据是8的倍数
    if len(cipher_data) % 8 != 0:
        log_error(f"Ciphertext length must be multiple of 8, got {len(cipher_data)}")
        raise ValueError("Ciphertext length must be multiple of 8")
    
    # CBC模式解密
    plaintext = bytearray()
    prev_block = iv_block
    
    for i in range(0, len(cipher_data), 8):
        block = cipher_data[i:i+8]
        block_64 = bytes_to_uint64(block)
        
        # 解密
        decrypted = des_decrypt_block(block_64, subkeys)
        
        # 与前一个密文块异或
        xor_block = decrypted ^ prev_block
        
        # 保存明文
        plaintext.extend(uint64_to_bytes(xor_block))
        prev_block = block_64
    
    # PKCS7去填充
    unpadded = pkcs7_unpad(bytes(plaintext))
    log_debug(f"Plaintext length after unpadding: {len(unpadded)} bytes")
    hexdump(unpadded, "Plaintext:")
    log_debug("=" * 50)
    
    return unpadded
