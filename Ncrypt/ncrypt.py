import hashlib
import os
import argparse
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def parse():
    parser = argparse.ArgumentParser(description="Specify a file for encryption or decryption using a specific or master key")

    parser.add_argument("-e", "--encrypt", help="Encrypt the target file. -k and -f arguments are required.", action="store_true")
    parser.add_argument("-d", "--decrypt", help="Decrypt the target file. -k and -f arguments required.", action="store_true")
    parser.add_argument("-s", "--hashfile", help="Generate a SHA256 hash of the specified file.", action="store_true")
    parser.add_argument("-k", "--key", type=str, help="Specify the key or password used for encryption or decryption.")
    parser.add_argument("-f", "--file", type=str, help="Specify the full path of the target file.")

    return parser.parse_args()

def deriveKey(string):
    sha256 = hashlib.sha256(string.encode()).digest()
    return sha256

def removeExt(path):
    root, ext = os.path.splitext(path)
    return root

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

        cutExt = removeExt(path)
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
    ext = input("\n[i] Specify the file extension to output the decrypted file as: ")
    try:
        decryptedData = unpad(cipher.decrypt(encryptedData), AES.block_size)

        with open(path, "wb") as decrypted:
            decrypted.write(decryptedData)

        cutExt = removeExt(path)
        decryptedPath = cutExt + ext
        os.rename(path, decryptedPath)

        print(f"\n[+] File decrypted: {decryptedPath}")
    except ValueError as e:
        print("[!] Failed to decrypt file. Invalid key or corrupted data.")

def hash():
    args = parse()
    file = args.file
    try:
        with open(file, "r") as f:
            data = f.read()
            sha256 = hashlib.sha256(data.encode()).hexdigest()
            print(f"\n[+] SHA256: {sha256}")
    except FileNotFoundError:
        print("\n[!] Error specified file is invalid or does not exist.")

args = parse()
if not args.hashfile and not args.encrypt and not args.decrypt:
    print("\n[!] No valid operation specified. Must specify whether encrypting, decrypting, or hashing.")
elif args.hashfile or args.encrypt or args.decrypt:
    trueCount = 0
    for i in (args.hashfile, args.encrypt, args.decrypt):
        if i == True:
            trueCount += 1
    if trueCount > 1:
        print("\n[!] Cannot specify more than one operation. (Encrypt, Decrypt, Hash)")
    else:
        if args.encrypt:
            if not args.key == None:
                if not args.file == None:
                    encrypt()
                else:
                    print("\n[!] No valid target file specified.")
            else:
                print("\n[!] No key for encryption specified.")
        elif args.decrypt:
            if not args.key == None:
                if not args.file == None:
                    decrypt()
                else:
                    print("\n[!] No valid target file specified.")
            else:
                print("\n[!] No key for decryption specified.")
        elif args.hashfile:
            if not args.file == None:
                hash()
            else:
                print("\n[!] No target file specified for hash operation.")