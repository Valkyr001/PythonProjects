import hashlib
import os
import argparse
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def parse():
    parser = argparse.ArgumentParser(description="Specify a file for encryption or decryption using a specific or master key")

    parser.add_argument("mode", choices=["encrypt","decrypt"], help="Set mode for either encryption or decryption.")
    parser.add_argument("-k", "--key", type=str, required=True, help="Specify the key or password used for encryption or decryption.")
    parser.add_argument("-f", "--file", type=str, required=True, help="Specify the file path for the file to operate on.")
    return parser.parse_args()

def deriveKey(string):
    sha256 = hashlib.sha256(string.encode()).digest()
    return sha256

def encrypt():
    args = parse()
    path = args.file
    key = deriveKey(args.key)
    iv = get_random_bytes(AES.block_size)

    print("\n[!] WARNING: This operation will completely overwrite the original file's contents.")
    print("[!] Please ensure that the encryption key is stored safely to avoid data loss.")
    print("[!] File will be converted to .aes")
    confirm = input("\n[!] Do you wish to proceed? (Y/N) ")

    if confirm == "Y":

        with open(path, "rb") as original:
            data = original.read()
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        paddedData = pad(data, AES.block_size)
        encryptedData = cipher.encrypt(paddedData)

        with open(path, "wb") as encrypted:
            encrypted.write(iv + encryptedData)

        cutExt = path[:-4]
        newPath = cutExt + ".aes"
        os.rename(path, newPath)

        print(f"\n[+] File encrypted and saved as {newPath}")

    else:
        return

def decrypt():
    args = parse()
    path = args.file
    key = deriveKey(args.key)

    with open(path, "rb") as encrypted:
        iv = encrypted.read(AES.block_size)
        encryptedData = encrypted.read()
    
    cipher = AES.new(key, AES.MODE_CBC, iv)

    try:
        decryptedData = unpad(cipher.decrypt(encryptedData), AES.block_size)

        with open(path, "wb") as decrypted:
            decrypted.write(decryptedData)

        cutExt = path[:-4]
        decryptedPath = cutExt + ".txt"
        os.rename(path, decryptedPath)

        print(f"\n[+] File decrypted: {decryptedPath}")
    except ValueError as e:
        print("[!] Failed to decrypt file. Invalid key or corrupted data.")
        print(f"[!] Error Info: {str(e)}")

args = parse()
if args.mode == "encrypt":
    encrypt()
elif args.mode == "decrypt":
    decrypt()
