import socket
from Crypto.Cipher import AES
import hashlib

def decrypt_packet(encrypted_packet, key):
    key = hashlib.sha256(key.encode()).digest()
    nonce = encrypted_packet[:16]
    ciphertext = encrypted_packet[16:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext).decode()
    return plaintext[10:]  

def start_server(server_address, key):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(server_address)
        s.listen()

        print('Server is listening...')
        conn, addr = s.accept()
        with conn:
            print('Connected by', addr)
            encrypted_message = conn.recv(1024)
            decrypted_message = decrypt_packet(encrypted_message, key)
            print('Decrypted message:', decrypted_message)

            conn.sendall(b'Received your encrypted message!')

# Пример использования
server_address = ('localhost', 65432)
key = 'supersecretkey'

start_server(server_address, key)
