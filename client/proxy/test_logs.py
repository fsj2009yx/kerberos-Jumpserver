"""测试 SSE 日志流格式"""

import requests
import time

def test_logs():
    url = "http://localhost:9884/api/logs"
    
    print("Connecting to SSE log stream...")
    print("Press Ctrl+C to stop")
    print("=" * 80)
    
    try:
        with requests.get(url, stream=True) as response:
            for line in response.iter_lines():
                if line:
                    line = line.decode('utf-8')
                    if line.startswith('data: '):
                        json_data = line[6:]  # Remove 'data: ' prefix
                        print(json_data)
                        print("-" * 80)
    except KeyboardInterrupt:
        print("\nStopped")

if __name__ == "__main__":
    test_logs()