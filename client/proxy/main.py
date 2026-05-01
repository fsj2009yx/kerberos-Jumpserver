"""Kerberos Client主入口"""

import argparse
import uvicorn
import sys
import os

# 添加当前目录到路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from api.server import app, init_config


def main():
    parser = argparse.ArgumentParser(description="Kerberos Client")
    parser.add_argument("--config", default="client_config.json", help="配置文件路径")
    parser.add_argument("--host", default="0.0.0.0", help="监听地址")
    parser.add_argument("--port", type=int, default=9883, help="监听端口")
    args = parser.parse_args()
    
    # 初始化配置
    init_config(args.config)
    
    # 启动API服务器
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()