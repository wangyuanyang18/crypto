import os
import json
import time
import getpass
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import random
import string

# 常量定义
CONFIG_FILE = 'password_config.json'
KEY_FILE = 'encryption.key'



# 生成AES密钥
def generate_aes_key():
    return os.urandom(32)  # 256位密钥

# 生成3位随机前缀  
def generate_prefix():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=3))

# 保存密钥到文件（带3位前缀的简单加密）
def save_key(key):
    # 生成3位随机前缀
    prefix = generate_prefix()
    # 编码密钥
    encoded_key = base64.b64encode(key).decode('utf-8')
    # 组合前缀和密钥
    encrypted_key = f'{prefix}{encoded_key}'
    # 写入文件
    with open(KEY_FILE, 'w') as f:
        f.write(encrypted_key)

# 从文件加载密钥（移除3位前缀解密）
def load_key():
    try:
        with open(KEY_FILE, 'r') as f:
            encrypted_key = f.read().strip()
        # 移除3位前缀
        if len(encrypted_key) > 3:
            encoded_key = encrypted_key[3:]  # 跳过前3位前缀
        else:
            encoded_key = encrypted_key
        # 解码密钥
        return base64.b64decode(encoded_key.encode('utf-8'))
    except (FileNotFoundError, Exception):
        return None

# AES加密函数
def aes_encrypt(data, key):
    iv = os.urandom(16)  # 16位IV
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode('utf-8')) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode('utf-8')

# AES解密函数
def aes_decrypt(encrypted_data, key):
    raw = base64.b64decode(encrypted_data)
    iv = raw[:16]
    ciphertext = raw[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data.decode('utf-8')

# 保存配置到文件（带乱码处理）
def save_config(config):
    # 转换配置为JSON
    config_json = json.dumps(config)
    # 写入文件
    with open(CONFIG_FILE, 'w') as f:
        f.write(config_json)

# 从文件加载配置（去除乱码）
def load_config():
    with open(CONFIG_FILE, 'r') as f:
        content = f.read()
    return json.loads(content)

# 首次运行设置
def setup_first_run():
    print("欢迎使用密码管理工具！这是您第一次运行，让我们进行初始设置。")
    
    # 设置密码（无格式限制）
    while True:
        password = input("请设置您要存储的密码: ")
        confirm_password = input("请再次输入密码: ")
        if password == confirm_password:
            break
        print("两次输入的密码不一致，请重新输入。")
    
    # 生成并保存密钥
    key = generate_aes_key()
    save_key(key)
    
    # 加密密码
    encrypted_password = aes_encrypt(password, key)
    
    # 保存配置（仅保存密码）
    config = {
        'password': encrypted_password
    }
    save_config(config)
    
    print("设置完成！您的密码已安全存储，可立即查看。")




# 查看密码
def view_password(key):
    config = load_config()
    encrypted_password = config['password']
    
    try:
        decrypted_password = aes_decrypt(encrypted_password, key)
        print(f"您的密码是: {decrypted_password}")
    except Exception as e:
        print("解密密码时出现错误。")

# 主函数
def main():
    # 检查是否首次运行
    if not os.path.exists(CONFIG_FILE) or not os.path.exists(KEY_FILE):
        setup_first_run()
    else:
        # 加载密钥
        try:
            key = load_key()
        except Exception as e:
            print("加载密钥失败。")
            return
        
        # 直接查看密码（身份验证码功能已移除）
        view_password(key)

if __name__ == "__main__":
    main()