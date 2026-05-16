"""生成客户端密钥和证书"""

import json
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


def gen_rsa_pair():
    """生成2048位RSA密钥对"""
    priv = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    pub = priv.public_key()
    numbers = pub.public_numbers()
    
    # 获取私钥参数
    priv_numbers = priv.private_numbers()
    
    return {
        'n': format(numbers.n, 'x').zfill(512),
        'e': format(numbers.e, 'x').zfill(6),
        'd': format(priv_numbers.d, 'x').zfill(512)
    }, {
        'n': format(numbers.n, 'x').zfill(512),
        'e': format(numbers.e, 'x').zfill(6)
    }


def create_certificate(entity_id, issuer, expire_date, priv_key):
    """创建自签名证书"""
    # 构造证书主体
    cert_body = {
        'id': entity_id,
        'issuer': issuer,
        'public_key': {
            'n': priv_key['n'],
            'e': priv_key['e']
        },
        'expire': expire_date
    }
    
    # 序列化并签名
    data_to_sign = json.dumps(cert_body, sort_keys=True).encode()
    
    # 转换私钥用于签名
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateNumbers
    from cryptography.hazmat.backends import default_backend
    
    pub_numbers = rsa.RSAPublicNumbers(
        e=int(priv_key['e'], 16),
        n=int(priv_key['n'], 16)
    )
    priv_numbers = RSAPrivateNumbers(
        p=None, q=None, dmp1=None, dmq1=None, iqmp=None,
        d=int(priv_key['d'], 16),
        public_numbers=pub_numbers
    )
    priv = priv_numbers.private_key(default_backend())
    
    signature = priv.sign(
        data_to_sign,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    
    cert_body['sign'] = signature.hex()
    return cert_body


def main():
    # 生成客户端密钥对
    client_priv, client_pub = gen_rsa_pair()
    
    # 创建客户端证书
    client_cert = create_certificate(
        'CLIENT_001',
        'MY_ROOT_CA',
        '2026-12-31',
        client_priv
    )
    
    # 保存文件
    import os
    
    # 创建目录
    os.makedirs('../certs', exist_ok=True)
    os.makedirs('../keys', exist_ok=True)
    
    # 保存私钥
    with open('../keys/client_priv.json', 'w') as f:
        json.dump(client_priv, f, indent=2)
    
    # 保存证书
    with open('../certs/cert_client.json', 'w') as f:
        json.dump(client_cert, f, indent=2)
    
    print("Client keys and certificate generated successfully.")
    print(f"Private key: ../keys/client_priv.json")
    print(f"Certificate: ../certs/cert_client.json")


if __name__ == '__main__':
    main()
