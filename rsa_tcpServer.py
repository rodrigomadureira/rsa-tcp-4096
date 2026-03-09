# -*- coding: utf-8 -*-

from socket import *
import json
import random
import struct

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
# AUXILIARES RSA
# =========================

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


def mod_inverse(e, phi):
    old_r, r = e, phi
    old_s, s = 1, 0

    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s

    if old_r != 1:
        raise ValueError("Nao existe inverso modular para e.")

    return old_s % phi


def is_probable_prime(n: int) -> bool:
    if n < 2:
        return False

    small = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    if n in small:
        return True

    for p in small:
        if n % p == 0:
            return False

    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    def witness(a: int) -> bool:
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            return True
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                return True
        return False

    if n < (1 << 64):
        bases = (2, 325, 9375, 28178, 450775, 9780504, 1795265022)
    else:
        k = 12
        bases = [random.randrange(2, n - 2) for _ in range(k)]

    for a in bases:
        a %= n
        if a == 0:
            continue
        if not witness(a):
            return False

    return True


def generate_prime(bits):
    while True:
        candidate = random.getrandbits(bits)
        candidate |= (1 << (bits - 1))
        candidate |= 1
        if is_probable_prime(candidate):
            return candidate


def generate_rsa_keys(bits=4096):
    half_bits = bits // 2

    print("[*] Gerando p...")
    p = generate_prime(half_bits)

    print("[*] Gerando q...")
    q = generate_prime(half_bits)
    while q == p:
        q = generate_prime(half_bits)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    if gcd(e, phi) != 1:
        e = 3
        while gcd(e, phi) != 1:
            e += 2

    d = mod_inverse(e, phi)
    return (e, n), (d, n)


# =========================
# CIFRA DE CESAR
# =========================

def caesar_decrypt(text, shift):
    result = ""
    for ch in text:
        result += chr((ord(ch) - shift) % 256)
    return result


# =========================
# RSA TEXTO
# =========================

def rsa_decrypt_list(cipher_list, d, n):
    chars = [chr(pow(c, d, n)) for c in cipher_list]
    return "".join(chars)


# =========================
# SERVER
# =========================

print("[*] Gerando chaves RSA de 4096 bits. Isso pode demorar...")
public_key, private_key = generate_rsa_keys(4096)
e, n = public_key
d, _ = private_key

print("\n[+] Chave publica gerada:")
print(f"e = {e}")
print(f"n = {n}")

serverSocket = socket(AF_INET, SOCK_STREAM)
serverSocket.bind(("", serverPort))
serverSocket.listen(5)

print(f"\n[+] TCP Server escutando na porta {serverPort}...\n")

connectionSocket, addr = serverSocket.accept()
print(f"[+] Conexao recebida de {addr}")

# 1) envia a chave publica
public_key_data = json.dumps({"e": e, "n": n}).encode("utf-8")
send_msg(connectionSocket, public_key_data)

# 2) recebe a mensagem criptografada inteira
data = recv_msg(connectionSocket)
cipher_json = data.decode("utf-8")
cipher_list = json.loads(cipher_json)

print(f"\n[+] Ciphertext recebido com {len(cipher_list)} blocos.")
print(f"[+] Primeiros 3 blocos: {cipher_list[:3]}")

# 3) descriptografa RSA
rsa_plain = rsa_decrypt_list(cipher_list, d, n)
print(f"\n[+] Apos descriptografia RSA:")
print(rsa_plain)

# 4) desfaz Cesar
original_text = caesar_decrypt(rsa_plain, CAESAR_SHIFT)
print(f"\n[+] Mensagem original recuperada:")
print(original_text)

# 5) responde ao client
response = f"Mensagem recebida com sucesso: {original_text}".encode("utf-8")
send_msg(connectionSocket, response)

connectionSocket.close()
serverSocket.close()