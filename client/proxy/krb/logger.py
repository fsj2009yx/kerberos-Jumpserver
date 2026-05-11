"""Kerberos日志记录器 - 生成Wireshark风格的日志格式"""

import uuid
from datetime import datetime
from typing import Dict, Any


class PacketLog:
    """数据包日志记录类"""
    
    def __init__(self, seq: int, source: str, destination: str, protocol: str, 
                 info: str, raw_data: bytes, decoded_lines: list = None):
        self.id = f"packet-{seq}"
        self.seq = seq
        self.timestamp = datetime.utcnow().isoformat() + "Z"
        self.source = source
        self.destination = destination
        self.protocol = protocol
        self.info = info
        self.raw = self._format_raw(raw_data)
        self.decoded = decoded_lines or []
    
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
               info: str, raw_data: bytes, decoded_lines: list = None):
    """记录数据包日志"""
    seq = runtime.consume_seq()
    packet_log = PacketLog(seq, source, destination, protocol, info, raw_data, decoded_lines)
    runtime.logs.append(packet_log)
    return packet_log