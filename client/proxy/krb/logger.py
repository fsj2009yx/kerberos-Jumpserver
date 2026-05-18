"""Kerberos日志记录器 - 生成Wireshark风格的日志格式"""

import json
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple, List

from krb.msg import KerHeader

MSG_TYPE_NAMES = {
    0x01: "AS_REQ",
    0x02: "AS_REP",
    0x03: "TGS_REQ",
    0x04: "TGS_REP",
    0x05: "AP_REQ",
    0x06: "AP_REP",
    0x07: "APP",
    0xff: "ERR",
}

PTY_OP_NAMES = {
    0x01: "OPEN",
    0x02: "INPUT",
    0x03: "RESIZE",
    0x04: "SIGNAL",
    0x05: "CLOSE",
}

PTY_EVENT_NAMES = {
    0x11: "OPEN_OK",
    0x12: "OUTPUT",
    0x13: "EXIT",
    0x14: "ERROR",
}


def decrypt_des_ecb(data: bytes, key: bytes) -> bytes:
    """DES-CBC解密（IV前置在密文头8字节）"""
    from crypto.des import decrypt_des_cbc
    result = decrypt_des_cbc(key, data)
    if result is None:
        return b""
    return result


def decrypt_payload(msg_type: int, payload: bytes, key: bytes) -> List[str]:
    """
    统一解密函数：自动识别消息类型，使用正确密钥解密所有加密字段
    并格式化输出：密文(hex)、明文(hex)、明文解析

    Args:
        msg_type: 消息类型 (0x01-0x06)
        payload: 原始payload数据
        key: 解密密钥 (bytes, 8字节)

    Returns:
        格式化后的解密输出行列表
    """
    lines = []

    try:
        if msg_type == 0x01:
            lines.extend(_decrypt_as_req(payload))
        elif msg_type == 0x02:
            lines.extend(_decrypt_as_rep(payload, key))
        elif msg_type == 0x03:
            lines.extend(_decrypt_tgs_req(payload, key))
        elif msg_type == 0x04:
            lines.extend(_decrypt_tgs_rep(payload, key))
        elif msg_type == 0x05:
            lines.extend(_decrypt_ap_req(payload, key))
        elif msg_type == 0x06:
            lines.extend(_decrypt_ap_rep(payload, key))
        elif msg_type == 0x07:
            lines.extend(_decrypt_app(payload))
        elif msg_type == 0xff:
            lines.extend(_decrypt_err(payload))
        else:
            lines.append(f"  [unknown msg_type 0x{msg_type:02x}]")
    except Exception as e:
        lines.append(f"  [decrypt error: {e}]")

    return lines


def _format_encrypted_field(name: str, cipher_hex: str, plain_hex: str, fields: List[Tuple[str, str]]) -> List[str]:
    """格式化加密字段的输出"""
    lines = []
    lines.append(f"  {name}:")
    lines.append(f"    密文(hex): {cipher_hex}")
    lines.append(f"    明文(hex): {plain_hex}")
    if fields:
        lines.append(f"    明文解析:")
        for field_name, field_value in fields:
            lines.append(f"      {field_name}: {field_value}")
    return lines


def _decrypt_kstring(data: bytes, offset: int) -> Tuple[Optional[str], int]:
    """解析KString: (string_value, new_offset)"""
    if offset + 2 > len(data):
        return None, offset
    str_len = int.from_bytes(data[offset:offset+2], 'big')
    if offset + 2 + str_len > len(data):
        return None, offset
    str_value = data[offset+2:offset+2+str_len].decode('utf-8', errors='replace')
    return str_value, offset + 2 + str_len


def _parse_authenticator_c(plain_data: bytes) -> List[Tuple[str, str]]:
    """解析Authenticator_c明文"""
    fields = []
    offset = 0

    id_client, offset = _decrypt_kstring(plain_data, offset)
    if id_client is not None:
        fields.append(("ID_Client", id_client))
    else:
        fields.append(("ID_Client", "[parse error]"))
        return fields

    if offset + 4 <= len(plain_data):
        ad_c = int.from_bytes(plain_data[offset:offset+4], 'big')
        fields.append(("AD_c", f"0x{ad_c:08x} ({ad_c})"))
        offset += 4

    if offset + 4 <= len(plain_data):
        ts = int.from_bytes(plain_data[offset:offset+4], 'big')
        fields.append(("TS", str(ts)))
        offset += 4

    return fields


def _parse_ticket_tgs(plain_data: bytes) -> List[Tuple[str, str]]:
    """解析Ticket_TGS明文 (由TGS服务器解密)"""
    fields = []
    offset = 0

    if len(plain_data) < 8:
        fields.append(("Key_c_tgs", f"[too short: {len(plain_data)} bytes]"))
        return fields

    key_c_tgs = plain_data[offset:offset+8]
    fields.append(("Key_c_tgs", key_c_tgs.hex()))
    offset += 8

    id_client, offset = _decrypt_kstring(plain_data, offset)
    if id_client is not None:
        fields.append(("ID_Client", id_client))
    else:
        fields.append(("ID_Client", "[parse error]"))
        return fields

    if offset + 4 <= len(plain_data):
        ad_c = int.from_bytes(plain_data[offset:offset+4], 'big')
        fields.append(("AD_c", f"0x{ad_c:08x} ({ad_c})"))
        offset += 4

    id_tgs, offset = _decrypt_kstring(plain_data, offset)
    if id_tgs is not None:
        fields.append(("ID_TGS", id_tgs))

    if offset + 4 <= len(plain_data):
        ts2 = int.from_bytes(plain_data[offset:offset+4], 'big')
        fields.append(("TS2", str(ts2)))
        offset += 4

    if offset + 4 <= len(plain_data):
        lifetime = int.from_bytes(plain_data[offset:offset+4], 'big')
        fields.append(("Lifetime", str(lifetime)))

    return fields


def _parse_ticket_v(plain_data: bytes) -> List[Tuple[str, str]]:
    """解析Ticket_V明文 (由V服务器解密)"""
    fields = []
    offset = 0

    if len(plain_data) < 8:
        fields.append(("Key_c_v", f"[too short: {len(plain_data)} bytes]"))
        return fields

    key_c_v = plain_data[offset:offset+8]
    fields.append(("Key_c_v", key_c_v.hex()))
    offset += 8

    id_client, offset = _decrypt_kstring(plain_data, offset)
    if id_client is not None:
        fields.append(("ID_Client", id_client))
    else:
        fields.append(("ID_Client", "[parse error]"))
        return fields

    if offset + 4 <= len(plain_data):
        ad_c = int.from_bytes(plain_data[offset:offset+4], 'big')
        fields.append(("AD_c", f"0x{ad_c:08x} ({ad_c})"))
        offset += 4

    id_v, offset = _decrypt_kstring(plain_data, offset)
    if id_v is not None:
        fields.append(("ID_V", id_v))

    if offset + 4 <= len(plain_data):
        ts4 = int.from_bytes(plain_data[offset:offset+4], 'big')
        fields.append(("TS4", str(ts4)))
        offset += 4

    if offset + 4 <= len(plain_data):
        lifetime = int.from_bytes(plain_data[offset:offset+4], 'big')
        fields.append(("Lifetime", str(lifetime)))

    return fields


def _decrypt_as_req(payload: bytes) -> List[str]:
    """解密AS_REQ (明文，无需解密)"""
    lines = []
    offset = 0

    id_client, offset = _decrypt_kstring(payload, offset)
    if id_client is not None:
        lines.append(f"  ID_Client: {id_client}")
    else:
        lines.append(f"  ID_Client: [parse error]")
        return lines

    id_tgs, offset = _decrypt_kstring(payload, offset)
    if id_tgs is not None:
        lines.append(f"  ID_TGS: {id_tgs}")
    else:
        lines.append(f"  ID_TGS: [parse error]")
        return lines

    if offset + 4 <= len(payload):
        ts1 = int.from_bytes(payload[offset:offset+4], 'big')
        lines.append(f"  TS1: {ts1}")

    return lines


def _decrypt_as_rep(payload: bytes, key: bytes) -> List[str]:
    """解密AS_REP: Enc_Part使用Kc解密，解密后包含Key_c_tgs, ID_TGS, TS2, Lifetime, Ticket_TGS"""
    lines = []

    if len(payload) < 4:
        lines.append(f"  [payload too short]")
        return lines

    cipher_len = int.from_bytes(payload[0:4], 'big')
    lines.append(f"  Cipher_Len: {cipher_len}")

    if len(payload) > 4:
        enc_part = payload[4:4+cipher_len] if cipher_len > 0 else payload[4:]
        if len(enc_part) > 0:
            try:
                plain_data = decrypt_des_ecb(enc_part, key)
                plain_hex = plain_data.hex()

                fields = []
                offset = 0

                if len(plain_data) >= 8:
                    key_c_tgs = plain_data[offset:offset+8]
                    fields.append(("Key_c_tgs", key_c_tgs.hex()))
                    offset += 8

                id_tgs, offset = _decrypt_kstring(plain_data, offset)
                if id_tgs is not None:
                    fields.append(("ID_TGS", id_tgs))

                if offset + 4 <= len(plain_data):
                    ts2 = int.from_bytes(plain_data[offset:offset+4], 'big')
                    fields.append(("TS2", str(ts2)))
                    offset += 4

                if offset + 4 <= len(plain_data):
                    lifetime = int.from_bytes(plain_data[offset:offset+4], 'big')
                    fields.append(("Lifetime", str(lifetime)))
                    offset += 4

                if offset + 4 <= len(plain_data):
                    ticket_len = int.from_bytes(plain_data[offset:offset+4], 'big')
                    fields.append(("Ticket_TGS_Len", str(ticket_len)))
                    offset += 4

                    if ticket_len > 0 and offset + ticket_len <= len(plain_data):
                        ticket_tgs = plain_data[offset:offset+ticket_len]
                        fields.append(("Ticket_TGS", f"[encrypted {len(ticket_tgs)} bytes]"))
                        fields.append(("Ticket_TGS(hex)", ticket_tgs.hex()))

                lines.extend(_format_encrypted_field("Enc_Part", enc_part.hex(), plain_hex, fields))

            except Exception as e:
                lines.append(f"  Enc_Part: [decrypt error: {e}]")
                lines.append(f"    密文(hex): {enc_part.hex()}")

    return lines


def _decrypt_tgs_req(payload: bytes, key_tgs: bytes) -> List[str]:
    """解密TGS_REQ: ID_V明文, Ticket_TGS用K_tgs解密, Authenticator_c用Key_c_tgs解密"""
    lines = []
    offset = 0

    id_v, offset = _decrypt_kstring(payload, offset)
    if id_v is not None:
        lines.append(f"  ID_V: {id_v}")
    else:
        lines.append(f"  ID_V: [parse error]")
        return lines

    if offset + 4 > len(payload):
        lines.append(f"  [payload truncated]")
        return lines

    ticket_len = int.from_bytes(payload[offset:offset+4], 'big')
    offset += 4
    lines.append(f"  Ticket_TGS_Len: {ticket_len}")

    if ticket_len > 0 and offset + ticket_len <= len(payload):
        ticket_tgs = payload[offset:offset+ticket_len]
        offset += ticket_len

        try:
            ticket_plain = decrypt_des_ecb(ticket_tgs, key_tgs)
            ticket_fields = _parse_ticket_tgs(ticket_plain)
            lines.extend(_format_encrypted_field("Ticket_TGS", ticket_tgs.hex(), ticket_plain.hex(), ticket_fields))
        except Exception:
            lines.extend(_format_encrypted_field("Ticket_TGS", ticket_tgs.hex(), "[仅TGS可解密]", [("说明", "Ticket_TGS 由 K_tgs 加密，客户端不持有该密钥")]))

    if offset + 4 > len(payload):
        lines.append(f"  [payload truncated]")
        return lines

    auth_len = int.from_bytes(payload[offset:offset+4], 'big')
    offset += 4
    lines.append(f"  Authenticator_c_Len: {auth_len}")

    if auth_len > 0 and offset + auth_len <= len(payload):
        auth_c = payload[offset:offset+auth_len]
        offset += auth_len

        key_c_tgs = key_tgs[:8] if len(key_tgs) >= 8 else key_tgs
        try:
            auth_plain = decrypt_des_ecb(auth_c, key_c_tgs)
            auth_fields = _parse_authenticator_c(auth_plain)
            lines.extend(_format_encrypted_field("Authenticator_c", auth_c.hex(), auth_plain.hex(), auth_fields))
        except Exception as e:
            lines.extend(_format_encrypted_field("Authenticator_c", auth_c.hex(), "[decrypt error]", [("Error", str(e))]))

    return lines


def _decrypt_tgs_rep(payload: bytes, key_c_tgs: bytes) -> List[str]:
    """解密TGS_REP: Enc_Part用Key_c_tgs解密，解密后包含Key_c_v, ID_V, TS4, Lifetime, Ticket_V"""
    lines = []

    if len(payload) < 4:
        lines.append(f"  [payload too short]")
        return lines

    cipher_len = int.from_bytes(payload[0:4], 'big')
    lines.append(f"  Cipher_Len: {cipher_len}")

    if len(payload) > 4:
        enc_part = payload[4:4+cipher_len] if cipher_len > 0 else payload[4:]
        if len(enc_part) > 0:
            try:
                plain_data = decrypt_des_ecb(enc_part, key_c_tgs)
                plain_hex = plain_data.hex()

                fields = []
                offset = 0

                if len(plain_data) >= 8:
                    key_c_v = plain_data[offset:offset+8]
                    fields.append(("Key_c_v", key_c_v.hex()))
                    offset += 8

                id_v, offset = _decrypt_kstring(plain_data, offset)
                if id_v is not None:
                    fields.append(("ID_V", id_v))

                if offset + 4 <= len(plain_data):
                    ts4 = int.from_bytes(plain_data[offset:offset+4], 'big')
                    fields.append(("TS4", str(ts4)))
                    offset += 4

                if offset + 4 <= len(plain_data):
                    lifetime = int.from_bytes(plain_data[offset:offset+4], 'big')
                    fields.append(("Lifetime", str(lifetime)))
                    offset += 4

                if offset + 4 <= len(plain_data):
                    ticket_v_len = int.from_bytes(plain_data[offset:offset+4], 'big')
                    fields.append(("Ticket_V_Len", str(ticket_v_len)))
                    offset += 4

                    if ticket_v_len > 0 and offset + ticket_v_len <= len(plain_data):
                        ticket_v = plain_data[offset:offset+ticket_v_len]
                        fields.append(("Ticket_V", f"[encrypted {len(ticket_v)} bytes]"))
                        fields.append(("Ticket_V(hex)", ticket_v.hex()))

                lines.extend(_format_encrypted_field("Enc_Part", enc_part.hex(), plain_hex, fields))

            except Exception as e:
                lines.append(f"  Enc_Part: [decrypt error: {e}]")
                lines.append(f"    密文(hex): {enc_part.hex()}")

    return lines


def _decrypt_ap_req(payload: bytes, key_c_v: bytes) -> List[str]:
    """解密AP_REQ: Ticket_V用K_v解密, Authenticator_c用Key_c_v解密"""
    lines = []
    offset = 0

    if offset + 4 > len(payload):
        lines.append(f"  [payload too short]")
        return lines

    ticket_v_len = int.from_bytes(payload[offset:offset+4], 'big')
    offset += 4
    lines.append(f"  Ticket_V_Len: {ticket_v_len}")

    if ticket_v_len > 0 and offset + ticket_v_len <= len(payload):
        ticket_v = payload[offset:offset+ticket_v_len]
        offset += ticket_v_len

        try:
            ticket_plain = decrypt_des_ecb(ticket_v, key_c_v)
            ticket_fields = _parse_ticket_v(ticket_plain)
            lines.extend(_format_encrypted_field("Ticket_V", ticket_v.hex(), ticket_plain.hex(), ticket_fields))
        except Exception:
            lines.extend(_format_encrypted_field("Ticket_V", ticket_v.hex(), "[仅服务端可解密]", [("说明", "Ticket_V 由 K_v 加密，客户端不持有该密钥")]))

    if offset + 4 > len(payload):
        lines.append(f"  [payload truncated]")
        return lines

    auth_len = int.from_bytes(payload[offset:offset+4], 'big')
    offset += 4
    lines.append(f"  Authenticator_c_Len: {auth_len}")

    if auth_len > 0 and offset + auth_len <= len(payload):
        auth_c = payload[offset:offset+auth_len]
        offset += auth_len

        try:
            auth_plain = decrypt_des_ecb(auth_c, key_c_v)
            auth_fields = _parse_authenticator_c(auth_plain)
            lines.extend(_format_encrypted_field("Authenticator_c", auth_c.hex(), auth_plain.hex(), auth_fields))
        except Exception as e:
            lines.extend(_format_encrypted_field("Authenticator_c", auth_c.hex(), "[decrypt error]", [("Error", str(e))]))

    return lines


def _decrypt_ap_rep(payload: bytes, key_c_v: bytes) -> List[str]:
    """解密AP_REP: Enc_Part用Key_c_v解密，解密后包含TS5+1"""
    lines = []

    if len(payload) < 4:
        lines.append(f"  [payload too short]")
        return lines

    cipher_len = int.from_bytes(payload[0:4], 'big')
    lines.append(f"  Cipher_Len: {cipher_len}")

    if len(payload) > 4:
        enc_part = payload[4:4+cipher_len] if cipher_len > 0 else payload[4:]
        if len(enc_part) > 0:
            try:
                plain_data = decrypt_des_ecb(enc_part, key_c_v) or b""
                plain_hex = plain_data.hex()

                fields = []
                if len(plain_data) >= 4:
                    ts5_plus_1 = int.from_bytes(plain_data[0:4], 'big')
                    fields.append(("TS5+1", str(ts5_plus_1)))
                    fields.append(("Verification", "AP_REP - Server confirmed receipt of AP_REQ"))

                lines.extend(_format_encrypted_field("Enc_Part", enc_part.hex(), plain_hex, fields))

            except Exception as e:
                lines.append(f"  Enc_Part: [decrypt error: {e}]")
                lines.append(f"    密文(hex): {enc_part.hex()}")

    return lines


def _decrypt_app(payload: bytes) -> List[str]:
    """解密APP业务消息 payload"""
    lines = []
    if len(payload) < 1:
        lines.append(f"  [payload too short]")
        return lines

    pty_op = payload[0]
    pty_op_name = PTY_OP_NAMES.get(pty_op, f"0x{pty_op:02x}")
    lines.append(f"  Pty_Op: {pty_op_name} (0x{pty_op:02x})")

    if len(payload) > 1:
        pty_payload = payload[1:]
        lines.append(f"  Payload: {len(pty_payload)} bytes")

        if pty_op == 0x01:
            lines.extend(_decrypt_pty_open(pty_payload))
        elif pty_op == 0x03:
            lines.extend(_decrypt_pty_resize(pty_payload))
        elif pty_op == 0x04:
            lines.extend(_decrypt_pty_signal(pty_payload))
        elif pty_op == 0x02:
            lines.append(f"    Input data(hex): {pty_payload.hex()}")
            try:
                lines.append(f"    As string: {pty_payload.decode('utf-8', errors='replace')}")
            except:
                pass
        else:
            lines.append(f"    hex: {pty_payload[:64].hex()}{'...' if len(pty_payload) > 64 else ''}")

    return lines


def _decrypt_pty_open(payload: bytes) -> List[str]:
    """解析PTY OPEN payload"""
    lines = []
    offset = 0

    if offset + 2 > len(payload):
        return lines

    term_len = int.from_bytes(payload[offset:offset+2], 'big')
    offset += 2

    if offset + term_len > len(payload):
        return lines

    term = payload[offset:offset+term_len].decode('utf-8', errors='replace')
    lines.append(f"    Term: {term}")
    offset += term_len

    if offset + 4 <= len(payload):
        cols = int.from_bytes(payload[offset:offset+2], 'big')
        rows = int.from_bytes(payload[offset+2:offset+4], 'big')
        lines.append(f"    Cols: {cols}, Rows: {rows}")

    return lines


def _decrypt_pty_resize(payload: bytes) -> List[str]:
    """解析PTY RESIZE payload"""
    lines = []
    if len(payload) >= 4:
        cols = int.from_bytes(payload[0:2], 'big')
        rows = int.from_bytes(payload[2:4], 'big')
        lines.append(f"    Cols: {cols}, Rows: {rows}")
    return lines


def _decrypt_pty_signal(payload: bytes) -> List[str]:
    """解析PTY SIGNAL payload"""
    lines = []
    if len(payload) >= 4:
        sig = int.from_bytes(payload[0:4], 'big')
        lines.append(f"    Signal: {sig}")
    return lines


def _decrypt_err(payload: bytes) -> List[str]:
    """解密ERR payload"""
    lines = []
    if len(payload) >= 4:
        err_code = int.from_bytes(payload[0:4], 'big')
        lines.append(f"  Error_Code: {err_code}")
    return lines


class PacketLog:
    """数据包日志记录类"""

    def __init__(self, seq: int, source: str, destination: str, protocol: str,
                 info: str, raw_data: bytes, decoded_lines: Optional[list] = None):
        self.id = f"packet-{seq}"
        self.seq = seq
        self.timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        self.source = source
        self.destination = destination
        self.protocol = protocol
        self.info = info
        self.raw = self._format_raw(raw_data)
        self.decoded = decoded_lines if decoded_lines is not None else self._decode_payload(raw_data)

    def _format_raw(self, data: bytes) -> list:
        """将原始字节数据格式化为十六进制转储格式"""
        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_str = " ".join(f"{b:02x}" for b in chunk)
            ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            lines.append(f"{i:04x}  {hex_str.ljust(47)}  {ascii_str}")
        return lines

    def _decode_payload(self, data: bytes) -> list:
        """根据msg_type解析payload为可读格式（不解密，仅显示结构）"""
        lines = []
        if len(data) < 20:
            lines.append(f"  [payload too short: {len(data)} bytes]")
            return lines

        try:
            header = KerHeader.from_bytes(data[:20])
            msg_type = header.msg_type
            msg_type_name = MSG_TYPE_NAMES.get(msg_type, f"0x{msg_type:02x}")
            payload = data[20:20 + header.total_len] if header.total_len > 0 else data[20:]

            lines.append(f"  msg_type: {msg_type_name} (0x{msg_type:02x})")
            lines.append(f"  seq_num: {header.seq_num}")
            lines.append(f"  timestamp: {header.timestamp}")
            lines.append(f"  payload_len: {len(payload)}")

            if len(payload) == 0:
                lines.append(f"  [no payload]")
                return lines

            lines.append("  --- Payload Decoded ---")

            pass  # decryption handled externally with correct keys

        except Exception as e:
            lines.append(f"  [decode error: {e}]")
            lines.append(f"  hex: {data[20:].hex() if len(data) > 20 else data.hex()}")

        return lines

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            "id": self.id,
            "seq": self.seq,
            "timestamp": self.timestamp,
            "source": self.source,
            "destination": self.destination,
            "protocol": self.protocol,
            "info": self.info,
            "raw": self.raw,
            "decoded": self.decoded
        }


def log_packet(runtime, source: str, destination: str, protocol: str,
               info: str, raw_data: bytes, decoded_lines: Optional[list] = None):
    """记录数据包日志"""
    seq = runtime.consume_seq()
    packet_log = PacketLog(seq, source, destination, protocol, info, raw_data, decoded_lines)
    runtime.logs.append(packet_log)
    return packet_log