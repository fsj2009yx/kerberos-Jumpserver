"""Kerberos消息结构定义"""

from dataclasses import dataclass, field
from typing import Any, Literal, Optional
import threading


ClientState = Literal["STATE_INIT", "STATE_AS_DONE", "STATE_TGS_DONE", "STATE_V_CONNECTED", "STATE_ERROR"]


@dataclass
class KString:
    length: int
    data: bytes
    
    def to_bytes(self) -> bytes:
        """转换为字节流（大端序）"""
        return (self.length >> 8).to_bytes(1, 'big') + \
               (self.length & 0xFF).to_bytes(1, 'big') + \
               self.data


@dataclass
class KerHeader:
    magic: int = 0x4B45  # 'KE'
    version: int = 0x01
    msg_type: int = 0x00
    total_len: int = 0
    seq_num: int = 0
    timestamp: int = 0
    addition: int = 0
    
    def to_bytes(self) -> bytes:
        """转换为字节流（大端序）"""
        return self.magic.to_bytes(2, 'big') + \
               self.version.to_bytes(1, 'big') + \
               self.msg_type.to_bytes(1, 'big') + \
               self.total_len.to_bytes(4, 'big') + \
               self.seq_num.to_bytes(4, 'big') + \
               self.timestamp.to_bytes(4, 'big') + \
               self.addition.to_bytes(4, 'big')
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'KerHeader':
        """从字节流解析（大端序）"""
        if len(data) < 20:
            raise ValueError("Header too short")
        return cls(
            magic=int.from_bytes(data[0:2], 'big'),
            version=data[2],
            msg_type=data[3],
            total_len=int.from_bytes(data[4:8], 'big'),
            seq_num=int.from_bytes(data[8:12], 'big'),
            timestamp=int.from_bytes(data[12:16], 'big'),
            addition=int.from_bytes(data[16:20], 'big')
        )


@dataclass
class ASReqPayload:
    id_client: KString
    id_tgs: KString
    ts1: int
    
    def to_bytes(self) -> bytes:
        """转换为字节流"""
        return self.id_client.to_bytes() + \
               self.id_tgs.to_bytes() + \
               self.ts1.to_bytes(4, 'big')
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'ASReqPayload':
        """从字节流解析"""
        # ID_Client
        len1 = int.from_bytes(data[0:2], 'big')
        id_client = KString(length=len1, data=data[2:2+len1])
        offset = 2 + len1
        
        # ID_TGS
        len2 = int.from_bytes(data[offset:offset+2], 'big')
        id_tgs = KString(length=len2, data=data[offset+2:offset+2+len2])
        offset += 2 + len2
        
        # TS1
        ts1 = int.from_bytes(data[offset:offset+4], 'big')
        
        return cls(id_client=id_client, id_tgs=id_tgs, ts1=ts1)


@dataclass
class ASRepPayloadWire:
    cipher_len: int
    enc_part: bytes
    
    def to_bytes(self) -> bytes:
        """转换为字节流"""
        return self.cipher_len.to_bytes(4, 'big') + self.enc_part
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'ASRepPayloadWire':
        """从字节流解析"""
        cipher_len = int.from_bytes(data[0:4], 'big')
        enc_part = data[4:4+cipher_len]
        return cls(cipher_len=cipher_len, enc_part=enc_part)


@dataclass
class ASRepPlain:
    key_c_tgs: bytes        # 8 bytes
    id_tgs: KString
    ts2: int
    lifetime: int
    ticket_len: int
    ticket_tgs: bytes
    
    def to_bytes(self) -> bytes:
        """转换为字节流"""
        return self.key_c_tgs + \
               self.id_tgs.to_bytes() + \
               self.ts2.to_bytes(4, 'big') + \
               self.lifetime.to_bytes(4, 'big') + \
               self.ticket_len.to_bytes(4, 'big') + \
               self.ticket_tgs
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'ASRepPlain':
        """从字节流解析"""
        key_c_tgs = data[0:8]
        offset = 8
        
        # ID_TGS
        len1 = int.from_bytes(data[offset:offset+2], 'big')
        id_tgs = KString(length=len1, data=data[offset+2:offset+2+len1])
        offset += 2 + len1
        
        # TS2
        ts2 = int.from_bytes(data[offset:offset+4], 'big')
        offset += 4
        
        # Lifetime
        lifetime = int.from_bytes(data[offset:offset+4], 'big')
        offset += 4
        
        # Ticket_Len
        ticket_len = int.from_bytes(data[offset:offset+4], 'big')
        offset += 4
        
        # Ticket_TGS
        ticket_tgs = data[offset:offset+ticket_len]
        
        return cls(
            key_c_tgs=key_c_tgs,
            id_tgs=id_tgs,
            ts2=ts2,
            lifetime=lifetime,
            ticket_len=ticket_len,
            ticket_tgs=ticket_tgs
        )


@dataclass
class TGSReqPayload:
    id_v: KString
    ticket_len: int
    ticket_tgs: bytes
    auth_len: int
    authenticator_c: bytes
    
    def to_bytes(self) -> bytes:
        """转换为字节流"""
        return self.id_v.to_bytes() + \
               self.ticket_len.to_bytes(4, 'big') + \
               self.ticket_tgs + \
               self.auth_len.to_bytes(4, 'big') + \
               self.authenticator_c
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'TGSReqPayload':
        """从字节流解析"""
        # ID_V
        len1 = int.from_bytes(data[0:2], 'big')
        id_v = KString(length=len1, data=data[2:2+len1])
        offset = 2 + len1
        
        # Ticket_Len
        ticket_len = int.from_bytes(data[offset:offset+4], 'big')
        offset += 4
        
        # Ticket_TGS
        ticket_tgs = data[offset:offset+ticket_len]
        offset += ticket_len
        
        # Auth_Len
        auth_len = int.from_bytes(data[offset:offset+4], 'big')
        offset += 4
        
        # Authenticator_c
        authenticator_c = data[offset:offset+auth_len]
        
        return cls(
            id_v=id_v,
            ticket_len=ticket_len,
            ticket_tgs=ticket_tgs,
            auth_len=auth_len,
            authenticator_c=authenticator_c
        )


@dataclass
class TGSRepPayloadWire:
    cipher_len: int
    enc_part: bytes
    
    def to_bytes(self) -> bytes:
        """转换为字节流"""
        return self.cipher_len.to_bytes(4, 'big') + self.enc_part
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'TGSRepPayloadWire':
        """从字节流解析"""
        cipher_len = int.from_bytes(data[0:4], 'big')
        enc_part = data[4:4+cipher_len]
        return cls(cipher_len=cipher_len, enc_part=enc_part)


@dataclass
class TGSRepPlain:
    key_c_v: bytes          # 8 bytes
    id_v: KString
    ts4: int
    lifetime: int
    ticket_v_len: int
    ticket_v: bytes
    
    def to_bytes(self) -> bytes:
        """转换为字节流"""
        return self.key_c_v + \
               self.id_v.to_bytes() + \
               self.ts4.to_bytes(4, 'big') + \
               self.lifetime.to_bytes(4, 'big') + \
               self.ticket_v_len.to_bytes(4, 'big') + \
               self.ticket_v
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'TGSRepPlain':
        """从字节流解析"""
        key_c_v = data[0:8]
        offset = 8
        
        # ID_V
        len1 = int.from_bytes(data[offset:offset+2], 'big')
        id_v = KString(length=len1, data=data[offset+2:offset+2+len1])
        offset += 2 + len1
        
        # TS4
        ts4 = int.from_bytes(data[offset:offset+4], 'big')
        offset += 4
        
        # Lifetime
        lifetime = int.from_bytes(data[offset:offset+4], 'big')
        offset += 4
        
        # Ticket_V_Len
        ticket_v_len = int.from_bytes(data[offset:offset+4], 'big')
        offset += 4
        
        # Ticket_V
        ticket_v = data[offset:offset+ticket_v_len]
        
        return cls(
            key_c_v=key_c_v,
            id_v=id_v,
            ts4=ts4,
            lifetime=lifetime,
            ticket_v_len=ticket_v_len,
            ticket_v=ticket_v
        )


@dataclass
class AuthenticatorPlain:
    id_client: KString
    ad_c: int
    ts: int
    
    def to_bytes(self) -> bytes:
        """转换为字节流"""
        return self.id_client.to_bytes() + \
               self.ad_c.to_bytes(4, 'big') + \
               self.ts.to_bytes(4, 'big')
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'AuthenticatorPlain':
        """从字节流解析"""
        # ID_Client
        len1 = int.from_bytes(data[0:2], 'big')
        id_client = KString(length=len1, data=data[2:2+len1])
        offset = 2 + len1
        
        # AD_c
        ad_c = int.from_bytes(data[offset:offset+4], 'big')
        offset += 4
        
        # TS
        ts = int.from_bytes(data[offset:offset+4], 'big')
        
        return cls(id_client=id_client, ad_c=ad_c, ts=ts)


@dataclass
class APReqPayload:
    ticket_v_len: int
    ticket_v: bytes
    auth_len: int
    authenticator_c: bytes
    
    def to_bytes(self) -> bytes:
        """转换为字节流"""
        return self.ticket_v_len.to_bytes(4, 'big') + \
               self.ticket_v + \
               self.auth_len.to_bytes(4, 'big') + \
               self.authenticator_c
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'APReqPayload':
        """从字节流解析"""
        ticket_v_len = int.from_bytes(data[0:4], 'big')
        ticket_v = data[4:4+ticket_v_len]
        offset = 4 + ticket_v_len
        
        auth_len = int.from_bytes(data[offset:offset+4], 'big')
        authenticator_c = data[offset+4:offset+4+auth_len]
        
        return cls(
            ticket_v_len=ticket_v_len,
            ticket_v=ticket_v,
            auth_len=auth_len,
            authenticator_c=authenticator_c
        )


@dataclass
class APRepPayloadWire:
    cipher_len: int
    enc_part: bytes
    
    def to_bytes(self) -> bytes:
        """转换为字节流"""
        return self.cipher_len.to_bytes(4, 'big') + self.enc_part
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'APRepPayloadWire':
        """从字节流解析"""
        cipher_len = int.from_bytes(data[0:4], 'big')
        enc_part = data[4:4+cipher_len]
        return cls(cipher_len=cipher_len, enc_part=enc_part)


@dataclass
class APRepPlain:
    ts5_plus_1: int
    
    def to_bytes(self) -> bytes:
        """转换为字节流"""
        return self.ts5_plus_1.to_bytes(4, 'big')
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'APRepPlain':
        """从字节流解析"""
        return cls(ts5_plus_1=int.from_bytes(data[0:4], 'big'))


@dataclass
class APPReqPlain:
    pty_op: int             # uint8
    pty_session_id: int     # uint32
    payload_len: int        # uint32
    payload: bytes
    
    def to_bytes(self) -> bytes:
        """转换为字节流"""
        return self.pty_op.to_bytes(1, 'big') + \
               self.pty_session_id.to_bytes(4, 'big') + \
               self.payload_len.to_bytes(4, 'big') + \
               self.payload
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'APPReqPlain':
        """从字节流解析"""
        pty_op = data[0]
        pty_session_id = int.from_bytes(data[1:5], 'big')
        payload_len = int.from_bytes(data[5:9], 'big')
        payload = data[9:9+payload_len]
        
        return cls(
            pty_op=pty_op,
            pty_session_id=pty_session_id,
            payload_len=payload_len,
            payload=payload
        )


@dataclass
class APPReqPayload:
    id_client: KString
    cipher_len: int         # uint16
    cipher_data: bytes
    rsa_sign_c: bytes       # 256 bytes
    
    def to_bytes(self) -> bytes:
        """转换为字节流"""
        return self.id_client.to_bytes() + \
               self.cipher_len.to_bytes(2, 'big') + \
               self.cipher_data + \
               self.rsa_sign_c
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'APPReqPayload':
        """从字节流解析"""
        # ID_Client
        len1 = int.from_bytes(data[0:2], 'big')
        id_client = KString(length=len1, data=data[2:2+len1])
        offset = 2 + len1
        
        # Cipher_Len
        cipher_len = int.from_bytes(data[offset:offset+2], 'big')
        offset += 2
        
        # Cipher_Data
        cipher_data = data[offset:offset+cipher_len]
        offset += cipher_len
        
        # RSA_Sign_c
        rsa_sign_c = data[offset:offset+256]
        
        return cls(
            id_client=id_client,
            cipher_len=cipher_len,
            cipher_data=cipher_data,
            rsa_sign_c=rsa_sign_c
        )


@dataclass
class APPRepPlain:
    pty_event: int          # uint8
    pty_session_id: int     # uint32
    exit_code: int          # int32
    payload_len: int        # uint32
    payload: bytes
    
    def to_bytes(self) -> bytes:
        """转换为字节流"""
        return self.pty_event.to_bytes(1, 'big') + \
               self.pty_session_id.to_bytes(4, 'big') + \
               self.exit_code.to_bytes(4, 'big', signed=True) + \
               self.payload_len.to_bytes(4, 'big') + \
               self.payload
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'APPRepPlain':
        """从字节流解析"""
        pty_event = data[0]
        pty_session_id = int.from_bytes(data[1:5], 'big')
        exit_code = int.from_bytes(data[5:9], 'big', signed=True)
        payload_len = int.from_bytes(data[9:13], 'big')
        payload = data[13:13+payload_len]
        
        return cls(
            pty_event=pty_event,
            pty_session_id=pty_session_id,
            exit_code=exit_code,
            payload_len=payload_len,
            payload=payload
        )


@dataclass
class APPRepPayload:
    cipher_len: int         # uint16
    cipher_data: bytes
    rsa_sign_v: bytes       # 256 bytes
    
    def to_bytes(self) -> bytes:
        """转换为字节流"""
        return self.cipher_len.to_bytes(2, 'big') + \
               self.cipher_data + \
               self.rsa_sign_v
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'APPRepPayload':
        """从字节流解析"""
        cipher_len = int.from_bytes(data[0:2], 'big')
        cipher_data = data[2:2+cipher_len]
        rsa_sign_v = data[2+cipher_len:2+cipher_len+256]
        
        return cls(
            cipher_len=cipher_len,
            cipher_data=cipher_data,
            rsa_sign_v=rsa_sign_v
        )


@dataclass
class TicketBundle:
    key_c_tgs: bytes = b""
    ticket_tgs: bytes = b""
    key_c_v: bytes = b""
    ticket_v: bytes = b""
    tgt_expire: int = 0
    tv_expire: int = 0


@dataclass
class ClientConfig:
    client_id: str
    ad_c: int
    as_addr: tuple[str, int]
    tgs_addr: tuple[str, int]
    v_addr: tuple[str, int]
    cert_path: str
    privkey_path: str
    v_cert_path: str = ""
    service_id: str = "verify_server"
    ticket_store_path: str = ""


@dataclass
class ClientRuntime:
    state: ClientState = "STATE_INIT"
    seq_num: int = 1
    session_id: Optional[str] = None
    v_sock: Optional[Any] = None
    bundle: TicketBundle = field(default_factory=TicketBundle)
    logs: list = field(default_factory=list)  # 存储 PacketLog 对象
    _seq_lock: Any = field(default_factory=threading.Lock, repr=False)

    def consume_seq(self) -> int:
        """返回本次发送使用的协议序号，并立即推进到下一个可用值。"""
        with self._seq_lock:
            seq = self.seq_num & 0xFFFFFFFF
            if seq == 0:
                seq = 1
            self.seq_num = 1 if seq == 0xFFFFFFFF else seq + 1
            return seq
