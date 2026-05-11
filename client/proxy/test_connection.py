#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
连接测试脚本 - 测试客户端与服务器的连接
"""
import socket
import json
import sys
import os

# 添加当前目录到路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_socket_connection(host, port, name):
    """测试socket连接"""
    print("\n" + "="*60)
    print("Testing connection to %s: %s:%d" % (name, host, port))
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)  # 5秒超时
        
        print("Connecting...")
        sock.connect((host, port))
        print("[OK] Connected successfully!")
        
        # 测试发送数据
        test_data = b'\x4B\x45\x01\x01\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00test'
        print("Sending test packet (%d bytes)..." % len(test_data))
        sock.sendall(test_data)
        
        # 尝试接收响应
        sock.settimeout(2)
        try:
            response = sock.recv(1024)
            print("Received response: %d bytes" % len(response))
            print("Response hex: %s" % response.hex())
        except socket.timeout:
            print("Timeout waiting for response (this may be expected)")
        
        sock.close()
        return True
        
    except ConnectionRefusedError:
        print("[FAIL] Connection refused - %s server not running?" % name)
        return False
    except socket.timeout:
        print("[FAIL] Connection timeout")
        return False
    except Exception as e:
        print("[FAIL] Error: %s" % str(e))
        return False

def test_config():
    """测试配置文件"""
    print("\n" + "="*60)
    print("Loading configuration...")
    
    config_path = "client_config.json"
    
    try:
        with open(config_path, 'r') as f:
            cfg_data = json.load(f)
        
        print("[OK] Configuration loaded successfully")
        print("Client ID: %s" % cfg_data['client_id'])
        print("AD_C: %d" % cfg_data['ad_c'])
        print("AS Server: %s:%d" % (cfg_data['as_host'], cfg_data['as_port']))
        print("TGS Server: %s:%d" % (cfg_data['tgs_host'], cfg_data['tgs_port']))
        print("V Server: %s:%d" % (cfg_data['v_host'], cfg_data['v_port']))
        print("Service ID: %s" % cfg_data.get('service_id', 'verify_server'))
        print("Cert Path: %s" % cfg_data['cert_path'])
        print("PrivKey Path: %s" % cfg_data['privkey_path'])
        
        # 检查路径是否存在
        cert_path = os.path.abspath(cfg_data['cert_path'])
        privkey_path = os.path.abspath(cfg_data['privkey_path'])
        
        if os.path.exists(cert_path):
            print("[OK] Certificate file exists: %s" % cert_path)
        else:
            print("[FAIL] Certificate file not found: %s" % cert_path)
        
        if os.path.exists(privkey_path):
            print("[OK] Private key file exists: %s" % privkey_path)
        else:
            print("[FAIL] Private key file not found: %s" % privkey_path)
        
        return cfg_data
        
    except FileNotFoundError:
        print("[FAIL] Configuration file not found: %s" % config_path)
        return None
    except json.JSONDecodeError:
        print("[FAIL] Invalid JSON in configuration file")
        return None

def test_packet_structure():
    """测试数据包结构"""
    print("\n" + "="*60)
    print("Testing packet structure...")
    
    # 构造一个测试包
    from krb.msg import KerHeader
    
    header = KerHeader(
        magic=0x4B45,
        version=0x01,
        msg_type=0x01,  # AS_REQ
        total_len=4,
        seq_num=1,
        timestamp=0,
        addition=0
    )
    
    header_bytes = header.to_bytes()
    payload = b'test'
    packet = header_bytes + payload
    
    print("Header length: %d bytes" % len(header_bytes))
    print("Header hex: %s" % header_bytes.hex())
    print("Payload length: %d bytes" % len(payload))
    print("Total packet length: %d bytes" % len(packet))
    
    # 解析测试
    parsed_header = KerHeader.from_bytes(header_bytes)
    print("\nParsed header:")
    print("  Magic: 0x%04X" % parsed_header.magic)
    print("  Version: 0x%02X" % parsed_header.version)
    print("  MsgType: 0x%02X" % parsed_header.msg_type)
    print("  TotalLen: %d" % parsed_header.total_len)
    print("  SeqNum: %d" % parsed_header.seq_num)
    
    # 验证
    assert parsed_header.magic == 0x4B45, "Magic mismatch"
    assert parsed_header.version == 0x01, "Version mismatch"
    assert parsed_header.total_len == 4, "TotalLen mismatch"
    print("[OK] Packet structure test passed")

def main():
    print("Kerberos Client Connection Test")
    print("="*60)
    
    # 测试配置
    cfg_data = test_config()
    if not cfg_data:
        print("\n[FAIL] Configuration load failed")
        return
    
    # 测试数据包结构
    test_packet_structure()
    
    # 测试连接
    if cfg_data:
        test_socket_connection(cfg_data['as_host'], cfg_data['as_port'], "AS Server")
        test_socket_connection(cfg_data['tgs_host'], cfg_data['tgs_port'], "TGS Server")
        test_socket_connection(cfg_data['v_host'], cfg_data['v_port'], "V Server")
    
    print("\n" + "="*60)
    print("Test completed")

if __name__ == "__main__":
    main()
