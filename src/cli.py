# src/cli.py
import argparse
from crypto import encrypt, decrypt
from stego import embed_bytes_into_image, extract_bytes_from_image
from pathlib import Path

def embed_cli(args):
    with open(args.message, 'rb') as f:
        plaintext = f.read()
    blob = encrypt(plaintext, args.passphrase)
    embed_bytes_into_image(args.cover, blob, args.out)
    print("Embedded successfully:", args.out)

def extract_cli(args):
    blob = extract_bytes_from_image(args.stego)
    plaintext = decrypt(blob, args.passphrase)
    if args.out:
        with open(args.out, 'wb') as f:
            f.write(plaintext)
        print("Saved extracted message to", args.out)
    else:
        print(plaintext.decode('utf-8', errors='replace'))

def main():
    parser = argparse.ArgumentParser(description="Secure Image Steganography")
    sub = parser.add_subparsers(dest='cmd')
    p1 = sub.add_parser('embed')
    p1.add_argument('--cover', required=True)
    p1.add_argument('--message', required=True, help="file containing message to hide (binary OK)")
    p1.add_argument('--passphrase', required=True)
    p1.add_argument('--out', required=True)
    p2 = sub.add_parser('extract')
    p2.add_argument('--stego', required=True)
    p2.add_argument('--passphrase', required=True)
    p2.add_argument('--out', required=False)
    args = parser.parse_args()
    if args.cmd == 'embed':
        embed_cli(args)
    elif args.cmd == 'extract':
        extract_cli(args)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
