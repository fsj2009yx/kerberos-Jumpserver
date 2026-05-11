#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
调试模式入口 - 启用详细日志记录
"""
import sys
import os

# 添加当前目录到路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 先初始化调试模块，设置调试级别
from debug.debug import set_debug_level, log_info, clear_log

# 设置详细调试级别 (0-5)
# 0=关闭, 1=错误, 2=警告, 3=信息, 4=详细, 5=调试
set_debug_level(5)

# 清空旧日志
clear_log()

log_info("=" * 70)
log_info("Kerberos Client - Debug Mode Enabled")
log_info("Debug Level: 5 (Maximum Verbosity)")
log_info("=" * 70)

# 导入并启动主程序
from api.server import app, init_config
import uvicorn

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Kerberos Client (Debug Mode)")
    parser.add_argument("--config", default="client_config.json", help="配置文件路径")
    parser.add_argument("--host", default="0.0.0.0", help="监听地址")
    parser.add_argument("--port", type=int, default=9883, help="监听端口")
    args = parser.parse_args()
    
    # 初始化配置
    init_config(args.config)
    
    log_info(f"Starting client on {args.host}:{args.port}")
    
    # 启动API服务器
    uvicorn.run(app, host=args.host, port=args.port)

if __name__ == "__main__":
    main()
