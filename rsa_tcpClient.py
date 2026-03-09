# -*- coding: utf-8 -*-

from socket import *
import json
import struct

serverName = "192.168.1.16"
serverPort = 1300
CAESAR_SHIFT = 3


# =========================
# AUXILIARES DE SOCKET
# =========================

def recv_exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("Conexao encerrada antes de receber todos os dados.")
        data += chunk
    return data


def send_msg(sock, data_bytes):
    header = struct.pack("!Q", len(data_bytes))
    sock.sendall(header + data_bytes)


def recv_msg(sock):
    header = recv_exact(sock, 8)
    msg_len = struct.unpack("!Q", header)[0]
    return recv_exact(sock, msg_len)


# =========================
# CIFRA DE CESAR
# =========================

def caesar_encrypt(text, shift):
    result = ""
    for ch in text:
        result += chr((ord(ch) + shift) % 256)
    return result


# =========================
# RSA TEXTO
# =========================

def rsa_encrypt_text(text, e, n):
    return [pow(ord(ch), e, n) for ch in text]


# =========================
# CLIENT
# =========================

clientSocket = socket(AF_INET, SOCK_STREAM)
clientSocket.connect((serverName, serverPort))

# 1) recebe a chave publica inteira
public_key_data = recv_msg(clientSocket).decode("utf-8")
public_key = json.loads(public_key_data)
e = public_key["e"]
n = public_key["n"]

print("[+] Chave publica recebida do servidor.")
print(f"e = {e}")
print(f"n = {n}")

# 2) le mensagem
sentence = input("Digite a mensagem: ")

# 3) aplica Cesar
caesar_text = caesar_encrypt(sentence, CAESAR_SHIFT)
print(f"[+] Apos Cifra de Cesar: {caesar_text}")

# 4) aplica RSA
cipher_list = rsa_encrypt_text(caesar_text, e, n)
print(f"[+] Ciphertext RSA gerado com {len(cipher_list)} blocos.")
print(f"[+] Primeiros 3 blocos: {cipher_list[:3]}")

# 5) envia a mensagem inteira
cipher_json = json.dumps(cipher_list).encode("utf-8")
send_msg(clientSocket, cipher_json)

# 6) recebe resposta inteira
response = recv_msg(clientSocket).decode("utf-8")
print("[+] Resposta do servidor:", response)

clientSocket.close()