"""Kerberos日志记录器 - 生成Wireshark风格的日志格式"""

import json
import uuid
from datetime import datetime
from typing import Dict, Any, Optional

from krb.msg import KerHeader


class PacketLog:
    """数据包日志记录类"""
    
    def __init__(self, seq: int, source: str, destination: str, protocol: str, 
                 info: str, raw_data: bytes, decoded_lines: Optional[list] = None):
        self.id = f"packet-{seq}"
        self.seq = seq
        self.timestamp = datetime.utcnow().isoformat() + "Z"
        self.source = source
        self.destination = destination
        self.protocol = protocol
        self.info = info
        self.raw = self._format_raw(raw_data)
        self.decoded = decoded_lines if decoded_lines is not None else self._decode_raw_to_json(raw_data)
    
    def _format_raw(self, data: bytes) -> list:
        """将原始字节数据格式化为十六进制转储格式"""
        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_str = " ".join(f"{b:02x}" for b in chunk)
            # 转换为可打印字符或点号
            ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            lines.append(f"{i:04x}  {hex_str.ljust(47)}  {ascii_str}")
        return lines

    def _decode_raw_to_json(self, data: bytes) -> list:
        """Best-effort decode of raw bytes into JSON lines for display."""
        summary: Dict[str, Any] = {
            "length": len(data),
            "hex": data.hex(),
            "ascii": "".join(chr(b) if 32 <= b <= 126 else "." for b in data),
        }
        if len(data) >= 20:
            try:
                header = KerHeader.from_bytes(data[:20])
                summary["header"] = {
                    "magic": header.magic,
                    "version": header.version,
                    "msg_type": header.msg_type,
                    "total_len": header.total_len,
                    "seq_num": header.seq_num,
                    "timestamp": header.timestamp,
                    "addition": header.addition,
                }
                payload = data[20:20 + header.total_len]
                summary["payload"] = {
                    "length": len(payload),
                    "hex": payload.hex(),
                    "ascii": "".join(chr(b) if 32 <= b <= 126 else "." for b in payload),
                }
            except Exception:
                pass
        return json.dumps(summary, indent=2).splitlines()
    
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