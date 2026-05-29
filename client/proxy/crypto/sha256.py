"""SHA-256哈希实现"""

# Initial hash values (H0-H7)
INITIAL_HASH = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]

# Round constants (K0-K63)
ROUND_CONSTANTS = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]


def right_rotate(value, bits):
    """32位循环右移"""
    return ((value >> bits) | (value << (32 - bits))) & 0xFFFFFFFF


def sha256_pad(data):
    """SHA-256消息填充"""
    original_len = len(data) * 8  # 原始长度（位）
    
    # 添加1位'1'
    padded = bytearray(data)
    padded.append(0x80)
    
    # 添加0位直到长度 ≡ 448 mod 512
    while (len(padded) * 8) % 512 != 448:
        padded.append(0x00)
    
    # 添加原始长度（64位大端）
    padded.append((original_len >> 56) & 0xFF)
    padded.append((original_len >> 48) & 0xFF)
    padded.append((original_len >> 40) & 0xFF)
    padded.append((original_len >> 32) & 0xFF)
    padded.append((original_len >> 24) & 0xFF)
    padded.append((original_len >> 16) & 0xFF)
    padded.append((original_len >> 8) & 0xFF)
    padded.append(original_len & 0xFF)
    
    return bytes(padded)


def sha256_compress(state, block):
    """SHA-256压缩函数"""
    # 初始化工作变量
    a, b, c, d, e, f, g, h = state
    
    # 将512位块分成16个32位字
    w = [0] * 64
    for i in range(16):
        w[i] = (block[i*4] << 24) | (block[i*4+1] << 16) | (block[i*4+2] << 8) | block[i*4+3]
    
    # 扩展为64个32位字
    for i in range(16, 64):
        s0 = right_rotate(w[i-15], 7) ^ right_rotate(w[i-15], 18) ^ (w[i-15] >> 3)
        s1 = right_rotate(w[i-2], 17) ^ right_rotate(w[i-2], 19) ^ (w[i-2] >> 10)
        w[i] = (w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFF
    
    # 64轮压缩
    for i in range(64):
        s1 = right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25)
        ch = (e & f) ^ (~e & g)
        temp1 = (h + s1 + ch + ROUND_CONSTANTS[i] + w[i]) & 0xFFFFFFFF
        s0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (s0 + maj) & 0xFFFFFFFF
        
        h = g
        g = f
        f = e
        e = (d + temp1) & 0xFFFFFFFF
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & 0xFFFFFFFF
    
    # 更新状态
    new_state = [
        (state[0] + a) & 0xFFFFFFFF,
        (state[1] + b) & 0xFFFFFFFF,
        (state[2] + c) & 0xFFFFFFFF,
        (state[3] + d) & 0xFFFFFFFF,
        (state[4] + e) & 0xFFFFFFFF,
        (state[5] + f) & 0xFFFFFFFF,
        (state[6] + g) & 0xFFFFFFFF,
        (state[7] + h) & 0xFFFFFFFF
    ]
    
    return new_state


def sha256(data):
    """计算SHA-256哈希"""
    # 初始化状态
    state = INITIAL_HASH.copy()
    
    # 消息填充
    padded = sha256_pad(data)
    
    # 分块处理（每块512位=64字节）
    for i in range(0, len(padded), 64):
        block = padded[i:i+64]
        state = sha256_compress(state, block)
    
    # 将状态转换为字节（大端序）
    digest = bytearray()
    for h in state:
        digest.extend(bytes([
            (h >> 24) & 0xFF,
            (h >> 16) & 0xFF,
            (h >> 8) & 0xFF,
            h & 0xFF
        ]))
    
    return bytes(digest)