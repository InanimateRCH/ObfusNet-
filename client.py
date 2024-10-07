
### 2. `client.py`
Этот файл содержит код клиента, который шифрует сообщение и отправляет его серверу.

```python
import socket
import random
import string
from Crypto.Cipher import AES
import hashlib

def generate_random_data(size):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=size))

def encrypt_packet(packet, key):
    key = hashlib.sha256(key.encode()).digest()
    cipher = AES.new(key, AES.MODE_GCM)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(packet.encode())
    return nonce + ciphertext

def send_encrypted_message(message, server_address, key):
    packet_with_noise = generate_random_data(10) + message  
    encrypted_message = encrypt_packet(packet_with_noise, key) 

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(server_address)
        s.sendall(encrypted_message)
        data = s.recv(1024)

    print('Received:', data.decode())

# Пример использования
server_address = ('localhost', 65432)  # IP и порт сервера
key = 'supersecretkey'
message = 'Hello, this is an encrypted message.'

send_encrypted_message(message, server_address, key)
