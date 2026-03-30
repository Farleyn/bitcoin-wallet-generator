import os
import sys
import time
import json
import csv
import argparse
import hashlib
import multiprocessing as mp

# secp256k1 curve constants
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424

def modinv(a, mod=P):
    # Extended Euclidean algorithm for modular inverse
    lm, hm = 1, 0
    low, high = a % mod, mod
    while low > 1:
        r = high // low
        lm, hm = hm - lm * r, lm
        low, high = high - low * r, low
    return lm % mod

def point_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p == q:
        return point_double(p)
    if p[0] == q[0] and (p[1] + q[1]) % P == 0:
        return None
    lam = ((q[1] - p[1]) * modinv(q[0] - p[0])) % P
    x = (lam * lam - p[0] - q[0]) % P
    y = (lam * (p[0] - x) - p[1]) % P
    return (x, y)

def point_double(p):
    lam = ((3 * p[0] * p[0]) * modinv(2 * p[1])) % P
    x = (lam * lam - 2 * p[0]) % P
    y = (lam * (p[0] - x) - p[1]) % P
    return (x, y)

def scalar_multiply(point, k):
    # Double-and-add from LSB to MSB
    result = None
    for i in range(k.bit_length()):
        if (k >> i) & 1:
            result = point_add(result, point)
        point = point_double(point)
    return result

def sha256(data):
    return hashlib.sha256(data).digest()

def ripemd160(data):
    h = hashlib.new('ripemd160')
    h.update(data)
    return h.digest()

def base58_encode(data):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    num = int.from_bytes(data, 'big')
    result = ''
    while num > 0:
        num, rem = divmod(num, 58)
        result = alphabet[rem] + result
    # preserve leading zero bytes as '1' characters
    pad = 0
    for byte in data:
        if byte == 0:
            pad += 1
        else:
            break
    return '1' * pad + result

def private_key_to_wif(priv_key, compressed=True):
    key_bytes = priv_key.to_bytes(32, 'big')
    if compressed:
        key_bytes += b'\x01'
    payload = b'\x80' + key_bytes
    checksum = sha256(sha256(payload))[:4]
    return base58_encode(payload + checksum)

def public_key_to_address(pub_key):
    pub_hash = ripemd160(sha256(pub_key))
    payload = b'\x00' + pub_hash
    checksum = sha256(sha256(payload))[:4]
    return base58_encode(payload + checksum)

def generate_private_key():
    while True:
        k = int.from_bytes(os.urandom(32), 'big')
        if 1 <= k < N:
            return k

def generate_wallet(index):
    priv = generate_private_key()
    pub_point = scalar_multiply((Gx, Gy), priv)
    x, y = pub_point
    prefix = b'\x02' if y % 2 == 0 else b'\x03'
    pub_key = prefix + x.to_bytes(32, 'big')
    return {
        "index": index,
        "private_key_hex": f"{priv:064x}",
        "private_key_wif": private_key_to_wif(priv),
        "address": public_key_to_address(pub_key),
    }

def export_wallets(wallets, fmt, filename):
    if fmt == 'txt':
        with open(filename, 'w') as f:
            for w in wallets:
                f.write(f"Wallet {w['index']}\n")
                f.write(f"Private Key (hex): {w['private_key_hex']}\n")
                f.write(f"Private Key (WIF): {w['private_key_wif']}\n")
                f.write(f"Address: {w['address']}\n\n")
    elif fmt == 'csv':
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=[
                "index", "private_key_hex", "private_key_wif", "address"
            ])
            writer.writeheader()
            writer.writerows(wallets)
    elif fmt == 'json':
        with open(filename, 'w') as f:
            json.dump(wallets, f, indent=2)

def main():
    parser = argparse.ArgumentParser(
        description="Bitcoin Wallet Generator - generates wallets with private keys and addresses"
    )
    parser.add_argument('-n', '--number', type=int, required=True,
                        help='Number of wallets to generate (must be >= 1)')
    parser.add_argument('-f', '--format', choices=['txt', 'csv', 'json'],
                        default='txt', help='Export format (default: txt)')
    parser.add_argument('-o', '--output', type=str, default=None,
                        help='Output file name (default: wallets.<format>)')
    args = parser.parse_args()
    if args.number < 1:
        print("Error: number of wallets must be at least 1.")
        sys.exit(1)
    filename = args.output if args.output else f"wallets.{args.format}"
    workers = min(args.number, os.cpu_count() or 1)
    print(f"Generating {args.number} wallet(s) using {workers} process(es)...")
    start_time = time.time()
    wallets = []
    with mp.Pool(processes=workers) as pool:
        for count, wallet in enumerate(pool.imap(generate_wallet, range(1, args.number + 1)), 1):
            wallets.append(wallet)
            print(f"\rProgress: {count}/{args.number}", end='', flush=True)
    print()
    print(f"Exporting to '{filename}' ({args.format.upper()})...")
    export_wallets(wallets, args.format, filename)
    elapsed = time.time() - start_time
    print(f"Done in {elapsed:.2f}s.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nCancelled.")
        sys.exit(0)
