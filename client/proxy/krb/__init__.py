"""Kerberos协议模块"""

import sys
import os

# 添加当前目录到路径，支持直接运行
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from krb.msg import ClientRuntime, ClientConfig, TicketBundle
from krb.krb import (
    client_do_as,
    client_do_tgs,
    client_do_ap,
    client_app_send_frame,
    krb_pack,
    krb_unpack,
    pack_as_req,
    unpack_as_rep,
    pack_tgs_req,
    unpack_tgs_rep,
    pack_ap_req,
    verify_ap_rep,
    pack_app_req,
    unpack_app_rep
)

__all__ = [
    'ClientRuntime',
    'ClientConfig',
    'TicketBundle',
    'client_do_as',
    'client_do_tgs',
    'client_do_ap',
    'client_app_send_frame',
    'krb_pack',
    'krb_unpack',
    'pack_as_req',
    'unpack_as_rep',
    'pack_tgs_req',
    'unpack_tgs_rep',
    'pack_ap_req',
    'verify_ap_rep',
    'pack_app_req',
    'unpack_app_rep'
]