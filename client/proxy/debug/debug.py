#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
调试模块 - 提供详细的日志记录和数据包分析功能
"""
import time
import struct
import os
from pathlib import Path
from datetime import datetime

# 调试级别
DEBUG_LEVEL = 3  # 0=关闭, 1=错误, 2=警告, 3=信息, 4=详细, 5=调试

# 日志文件路径
def _resolve_log_file():
    log_dir = os.environ.get("KRB_CLIENT_LOG_DIR", "").strip()
    if log_dir:
        target_dir = Path(log_dir)
        target_dir.mkdir(parents=True, exist_ok=True)
        return str(target_dir / "client_debug.log")
    return str(Path(__file__).resolve().parents[1] / "client_debug.log")

LOG_FILE = _resolve_log_file()

def set_debug_level(level):
    """设置调试级别"""
    global DEBUG_LEVEL
    DEBUG_LEVEL = level

def get_timestamp():
    """获取当前时间戳字符串"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

def log(level, message, *args):
    """通用日志函数"""
    if level > DEBUG_LEVEL:
        return
    
    levels = ["", "ERROR", "WARN", "INFO", "DETAIL", "DEBUG"]
    prefix = f"[{get_timestamp()}] [{levels[level]}]"
    
    if args:
        message = message % args
    
    # 输出到控制台
    print(f"{prefix} {message}", flush=True)
    
    # 输出到文件
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"{prefix} {message}\n")
    except OSError:
        pass

def log_error(message, *args):
    """记录错误日志"""
    log(1, message, *args)

def log_warn(message, *args):
    """记录警告日志"""
    log(2, message, *args)

def log_info(message, *args):
    """记录信息日志"""
    log(3, message, *args)

def log_detail(message, *args):
    """记录详细日志"""
    log(4, message, *args)

def log_debug(message, *args):
    """记录调试日志"""
    log(5, message, *args)

def hexdump(data, prefix="", max_bytes=1024):
    """十六进制转储"""
    if len(data) == 0:
        log_detail(f"{prefix} Empty data")
        return
    
    data = data[:max_bytes]
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_str = " ".join(f"{b:02X}" for b in chunk)
        ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{i:04X}: {hex_str:<47} |{ascii_str}|")
    
    log_detail(f"{prefix} Hex dump ({len(data)} bytes):")
    for line in lines:
        log_detail(f"  {line}")

def log_packet(header, payload=None):
    """记录数据包信息"""
    log_detail("=" * 60)
    log_detail(f"Packet Header:")
    log_detail(f"  Magic: 0x{header.get('magic', 0):04X}")
    log_detail(f"  Version: 0x{header.get('version', 0):02X}")
    log_detail(f"  MsgType: 0x{header.get('msg_type', 0):02X} ({get_msg_type_name(header.get('msg_type', 0))})")
    log_detail(f"  TotalLen: {header.get('total_len', 0)}")
    log_detail(f"  SeqNum: {header.get('seq_num', 0)}")
    log_detail(f"  Timestamp: {header.get('timestamp', 0)} ({time.ctime(header.get('timestamp', 0))})")
    
    if payload is not None:
        log_detail(f"  Payload: {len(payload)} bytes")
        hexdump(payload, "  ")
    
    log_detail("=" * 60)

def get_msg_type_name(msg_type):
    """获取消息类型名称"""
    types = {
        0x01: "AS_REQ",
        0x02: "AS_REP",
        0x03: "TGS_REQ",
        0x04: "TGS_REP",
        0x05: "AP_REQ",
        0x06: "AP_REP",
        0x07: "APP_REQ/REP",
        0xFF: "ERROR"
    }
    return types.get(msg_type, f"UNKNOWN({msg_type})")

def log_state_change(old_state, new_state):
    """记录状态变化"""
    log_info(f"State changed: [{old_state}] -> [{new_state}]")

def log_encryption(key_name, key_value, plaintext, ciphertext):
    """记录加密操作"""
    log_debug(f"Encryption [{key_name}]:")
    log_debug(f"  Key: {key_value.hex()}")
    log_debug(f"  Plaintext: {len(plaintext)} bytes")
    hexdump(plaintext, "    Plain:")
    log_debug(f"  Ciphertext: {len(ciphertext)} bytes")
    hexdump(ciphertext, "    Cipher:")

def log_decryption(key_name, key_value, ciphertext, plaintext):
    """记录解密操作"""
    log_debug(f"Decryption [{key_name}]:")
    log_debug(f"  Key: {key_value.hex()}")
    log_debug(f"  Ciphertext: {len(ciphertext)} bytes")
    hexdump(ciphertext, "    Cipher:")
    log_debug(f"  Plaintext: {len(plaintext)} bytes")
    hexdump(plaintext, "    Plain:")

def log_kstring(name, kstring):
    """记录KString数据"""
    log_debug(f"KString [{name}]: length={kstring.length}, data={kstring.data.decode('utf-8', errors='replace')}")

def log_authenticator(auth):
    """记录Authenticator信息"""
    log_debug(f"Authenticator:")
    log_debug(f"  ID_Client: {auth.id_client.data.decode('utf-8', errors='replace')}")
    log_debug(f"  AD_C: {auth.ad_c}")
    log_debug(f"  TS: {auth.ts}")

def log_ticket(ticket):
    """记录票据信息"""
    log_debug(f"Ticket: {len(ticket)} bytes")
    hexdump(ticket, "  ")

def log_error_code(code):
    """记录错误码"""
    errors = {
        -1001: "ERR_MAGIC_MISMATCH",
        -1002: "ERR_VERSION_UNSUPPORTED",
        -1003: "ERR_MSG_TYPE_INVALID",
        -1004: "ERR_PAYLOAD_TOO_LARGE",
        -1005: "ERR_REPLAY_TIMESTAMP",
        -1006: "ERR_REPLAY_SEQ",
        -1007: "ERR_BUF_TOO_SMALL",
        -1008: "ERR_SOCKET_SEND",
        -1009: "ERR_SOCKET_RECV",
        -2001: "ERR_CLIENT_NOT_FOUND",
        -2002: "ERR_TICKET_EXPIRED",
        -2003: "ERR_TICKET_INVALID",
        -2004: "ERR_AUTH_MISMATCH",
        -2005: "ERR_AD_MISMATCH",
        -2006: "ERR_KEY_DERIVE",
        -2007: "ERR_SESSION_NOT_FOUND",
        -3001: "ERR_DES_KEY_LEN",
        -3002: "ERR_DES_PADDING",
        -3003: "ERR_DES_DECRYPT_FAIL",
        -3004: "ERR_RSA_KEY_INVALID",
        -3005: "ERR_RSA_SIGN_FAIL",
        -3006: "ERR_RSA_VERIFY_FAIL"
    }
    log_error(f"Error code: {code} ({errors.get(code, 'UNKNOWN')})")

def clear_log():
    """清空日志文件"""
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)
        log_info("Debug log cleared")

def print_connection_status(host, port, connected):
    """打印连接状态"""
    if connected:
        log_info(f"Connected to {host}:{port}")
    else:
        log_error(f"Failed to connect to {host}:{port}")

def validate_packet_structure(raw_data):
    """验证数据包结构"""
    log_debug("Validating packet structure...")
    
    if len(raw_data) < 20:
        log_error(f"Packet too short: {len(raw_data)} bytes")
        return False
    
    # 解析头部
    magic = struct.unpack('>H', raw_data[:2])[0]
    version = raw_data[2]
    msg_type = raw_data[3]
    total_len = struct.unpack('>I', raw_data[4:8])[0]
    seq_num = struct.unpack('>I', raw_data[8:12])[0]
    timestamp = struct.unpack('>I', raw_data[12:16])[0]
    
    log_debug(f"Magic: 0x{magic:04X} (expected: 0x4B45)")
    log_debug(f"Version: 0x{version:02X} (expected: 0x01)")
    log_debug(f"MsgType: 0x{msg_type:02X}")
    log_debug(f"TotalLen: {total_len}")
    log_debug(f"SeqNum: {seq_num}")
    log_debug(f"Timestamp: {timestamp}")
    
    if magic != 0x4B45:
        log_error(f"Magic mismatch: expected 0x4B45, got 0x{magic:04X}")
        return False
    
    if version != 0x01:
        log_error(f"Version mismatch: expected 0x01, got 0x{version:02X}")
        return False
    
    expected_total = 20 + total_len
    if len(raw_data) != expected_total:
        log_error(f"Packet length mismatch: expected {expected_total}, got {len(raw_data)}")
        return False
    
    log_debug("Packet structure is valid")
    return True
