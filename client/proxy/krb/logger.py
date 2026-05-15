"""Kerberos日志记录器 - 生成Wireshark风格的日志格式"""

import json
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional

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

    def _decode_kstring(self, data: bytes, offset: int) -> tuple:
        """解析KString: (string_value, new_offset)"""
        if offset + 2 > len(data):
            return None, offset
        str_len = int.from_bytes(data[offset:offset+2], 'big')
        if offset + 2 + str_len > len(data):
            return None, offset
        str_value = data[offset+2:offset+2+str_len].decode('utf-8', errors='replace')
        return str_value, offset + 2 + str_len

    def _decode_payload(self, data: bytes) -> list:
        """根据msg_type解析payload为可读格式"""
        lines = []
        if len(data) < 20:
            lines.append(f"  [payload too short: {len(data)} bytes]")
            return lines

        try:
            header = KerHeader.from_bytes(data[:20])
            msg_type = header.msg_type
            msg_type_name = MSG_TYPE_NAMES.get(msg_type, f"0x{msg_type:02x}")
            payload = data[20:20 + header.total_len] if header.total_len > 0 else data[20:]
            offset = 0

            lines.append(f"  msg_type: {msg_type_name} (0x{msg_type:02x})")
            lines.append(f"  seq_num: {header.seq_num}")
            lines.append(f"  timestamp: {header.timestamp}")
            lines.append(f"  payload_len: {len(payload)}")

            if len(payload) == 0:
                lines.append(f"  [no payload]")
                return lines

            lines.append("  --- Payload Decoded ---")

            if msg_type == 0x01:
                lines.extend(self._decode_as_req(payload))
            elif msg_type == 0x02:
                lines.extend(self._decode_as_rep(payload))
            elif msg_type == 0x03:
                lines.extend(self._decode_tgs_req(payload))
            elif msg_type == 0x04:
                lines.extend(self._decode_tgs_rep(payload))
            elif msg_type == 0x05:
                lines.extend(self._decode_ap_req(payload))
            elif msg_type == 0x06:
                lines.extend(self._decode_ap_rep(payload))
            elif msg_type == 0x07:
                lines.extend(self._decode_app(payload))
            elif msg_type == 0xff:
                lines.extend(self._decode_err(payload))
            else:
                lines.append(f"  [unknown msg_type 0x{msg_type:02x}, showing raw]")
                lines.append(f"  hex: {payload.hex()}")

        except Exception as e:
            lines.append(f"  [decode error: {e}]")
            lines.append(f"  hex: {data[20:].hex() if len(data) > 20 else data.hex()}")

        return lines

    def _decode_as_req(self, payload: bytes) -> list:
        """解析AS_REQ payload"""
        lines = []
        offset = 0

        id_client, offset = self._decode_kstring(payload, offset)
        if id_client is not None:
            lines.append(f"  ID_Client: {id_client}")
        else:
            lines.append(f"  ID_Client: [parse error]")
            return lines

        id_tgs, offset = self._decode_kstring(payload, offset)
        if id_tgs is not None:
            lines.append(f"  ID_TGS: {id_tgs}")
        else:
            lines.append(f"  ID_TGS: [parse error]")
            return lines

        if offset + 4 <= len(payload):
            ts1 = int.from_bytes(payload[offset:offset+4], 'big')
            lines.append(f"  TS1: {ts1}")

        return lines

    def _decode_as_rep(self, payload: bytes) -> list:
        """解析AS_REP payload (加密)"""
        lines = []
        if len(payload) < 4:
            lines.append(f"  [payload too short]")
            return lines

        cipher_len = int.from_bytes(payload[0:4], 'big')
        lines.append(f"  Cipher_Len: {cipher_len}")

        if len(payload) > 4:
            enc_part = payload[4:4+cipher_len] if cipher_len > 0 else payload[4:]
            if len(enc_part) > 0:
                lines.append(f"  Enc_Part: [encrypted, {len(enc_part)} bytes]")
                lines.append(f"    hex: {enc_part[:32].hex()}{'...' if len(enc_part) > 32 else ''}")

        return lines

    def _decode_tgs_req(self, payload: bytes) -> list:
        """解析TGS_REQ payload"""
        lines = []
        offset = 0

        id_v, offset = self._decode_kstring(payload, offset)
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
            lines.append(f"  Ticket_TGS: [encrypted, {len(ticket_tgs)} bytes]")
            lines.append(f"    hex: {ticket_tgs[:32].hex()}{'...' if len(ticket_tgs) > 32 else ''}")

        if offset + 4 > len(payload):
            lines.append(f"  [payload truncated]")
            return lines

        auth_len = int.from_bytes(payload[offset:offset+4], 'big')
        offset += 4
        lines.append(f"  Authenticator_c_Len: {auth_len}")

        if auth_len > 0 and offset + auth_len <= len(payload):
            auth_c = payload[offset:offset+auth_len]
            lines.append(f"  Authenticator_c: [encrypted, {len(auth_c)} bytes]")
            lines.append(f"    hex: {auth_c[:32].hex()}{'...' if len(auth_c) > 32 else ''}")

        return lines

    def _decode_tgs_rep(self, payload: bytes) -> list:
        """解析TGS_REP payload (加密)"""
        lines = []
        if len(payload) < 4:
            lines.append(f"  [payload too short]")
            return lines

        cipher_len = int.from_bytes(payload[0:4], 'big')
        lines.append(f"  Cipher_Len: {cipher_len}")

        if len(payload) > 4:
            enc_part = payload[4:4+cipher_len] if cipher_len > 0 else payload[4:]
            if len(enc_part) > 0:
                lines.append(f"  Enc_Part: [encrypted, {len(enc_part)} bytes]")
                lines.append(f"    hex: {enc_part[:32].hex()}{'...' if len(enc_part) > 32 else ''}")

        return lines

    def _decode_ap_req(self, payload: bytes) -> list:
        """解析AP_REQ payload"""
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
            lines.append(f"  Ticket_V: [encrypted, {len(ticket_v)} bytes]")
            lines.append(f"    hex: {ticket_v[:32].hex()}{'...' if len(ticket_v) > 32 else ''}")

        if offset + 4 > len(payload):
            lines.append(f"  [payload truncated]")
            return lines

        auth_len = int.from_bytes(payload[offset:offset+4], 'big')
        offset += 4
        lines.append(f"  Authenticator_c_Len: {auth_len}")

        if auth_len > 0 and offset + auth_len <= len(payload):
            auth_c = payload[offset:offset+auth_len]
            lines.append(f"  Authenticator_c: [encrypted, {len(auth_c)} bytes]")
            lines.append(f"    hex: {auth_c[:32].hex()}{'...' if len(auth_c) > 32 else ''}")

        return lines

    def _decode_ap_rep(self, payload: bytes) -> list:
        """解析AP_REP payload"""
        lines = []
        if len(payload) < 4:
            lines.append(f"  [payload too short]")
            return lines

        cipher_len = int.from_bytes(payload[0:4], 'big')
        lines.append(f"  Cipher_Len: {cipher_len}")

        if len(payload) > 4:
            enc_part = payload[4:4+cipher_len] if cipher_len > 0 else payload[4:]
            if len(enc_part) > 0:
                lines.append(f"  Enc_Part: [encrypted, {len(enc_part)} bytes]")
                lines.append(f"    hex: {enc_part[:32].hex()}{'...' if len(enc_part) > 32 else ''}")

        return lines

    def _decode_app(self, payload: bytes) -> list:
        """解析APP业务消息 payload"""
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
                lines.extend(self._decode_pty_open(pty_payload))
            elif pty_op == 0x03:
                lines.extend(self._decode_pty_resize(pty_payload))
            elif pty_op == 0x04:
                lines.extend(self._decode_pty_signal(pty_payload))
            elif pty_op == 0x02:
                lines.append(f"    Input data: {pty_payload.hex()}")
                try:
                    lines.append(f"    As string: {pty_payload.decode('utf-8', errors='replace')}")
                except:
                    pass
            else:
                lines.append(f"    hex: {pty_payload[:64].hex()}{'...' if len(pty_payload) > 64 else ''}")

        return lines

    def _decode_pty_open(self, payload: bytes) -> list:
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

    def _decode_pty_resize(self, payload: bytes) -> list:
        """解析PTY RESIZE payload"""
        lines = []
        if len(payload) >= 4:
            cols = int.from_bytes(payload[0:2], 'big')
            rows = int.from_bytes(payload[2:4], 'big')
            lines.append(f"    Cols: {cols}, Rows: {rows}")
        return lines

    def _decode_pty_signal(self, payload: bytes) -> list:
        """解析PTY SIGNAL payload"""
        lines = []
        if len(payload) >= 4:
            sig = int.from_bytes(payload[0:4], 'big')
            lines.append(f"    Signal: {sig}")
        return lines

    def _decode_err(self, payload: bytes) -> list:
        """解析ERR payload"""
        lines = []
        if len(payload) >= 4:
            err_code = int.from_bytes(payload[0:4], 'big')
            lines.append(f"  Error_Code: {err_code}")
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