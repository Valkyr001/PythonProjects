import hashlib
import os
import argparse
import getpass
import datetime
import re
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
    parser.add_argument("-sV", "--savevault", help="Store the passkey used in the current operation to the vault file. Must be used with -e", action="store_true")
    parser.add_argument("-mV", "--makevault", help="Create a vault file.", action="store_true")
    parser.add_argument("-rV", "--readvault", help="Decrypt and read the contents of the vault file. Master key required.", action="store_true")
    parser.add_argument("-cV", "--clearvault", help="Delete the vault file and permanantly wipe its contents.", action="store_true")

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
    confirm = input("\n[!] Do you wish to proceed? (Y/N): ")

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
    if re.match(r"(\.[a-zA-Z]{3,4})", ext):
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
    else:
        print("[!] Invalid file extension entered.")

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

def makeVault():
    vaultFile = "vault.aes"
    if os.path.exists(vaultFile):
        print("\n[!] Cannot create a vault file when one already exists.")
        return
    else:
        masterKey1 = getpass.getpass("\n[i] Create a master key to encrypt/decrypt the vault file: ")
        masterKey2 = getpass.getpass("[i] Re-enter your new master key: ")
        if masterKey1 == masterKey2:
            iv = get_random_bytes(AES.block_size)
            key = deriveKey(masterKey1)
            timestamp = datetime.datetime.now()
            with open(vaultFile, "w") as vaultInit:
                vaultInit.write(f"--Vault Created: {timestamp}--")
            with open(vaultFile, "rb") as vaultRead:
                data = vaultRead.read()

            cipher = AES.new(key, AES.MODE_CBC, iv)
            padded = pad(data, AES.block_size)
            encrypted = cipher.encrypt(padded)
            try:
                with open(vaultFile, "wb") as vaultWrite:
                    vaultWrite.write(iv + encrypted)
                print(f"[+] Vault created successfully. Location: Ncrypt/{vaultFile}")
            except ValueError:
                print("[!] Error occured while creating the vault file.")
                print(f"[!] Error Details: {ValueError}")

        else:
            print("[!] Master keys do not match. Exiting.")
            return
        
def readVault():
    vaultFile = "vault.aes"
    if os.path.exists(vaultFile):
        masterKey = getpass.getpass("[i] Enter your master key: ")
        key = deriveKey(masterKey)
        with open(vaultFile, "rb") as readVault:
            getData = readVault.read()

        iv = getData[:AES.block_size]
        ciphertext = getData[AES.block_size:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        try:
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
            print("[+] Decrypted Contents:")
            print(plaintext.decode("utf-8"))
        except ValueError:
            print(f"\n[!] Error while decrypting the vault file: {ValueError}")
    else:
        print("\n[!] No vault file exists. You can create one with ncrypt.py -mV")

def clearVault():
    vaultFile = "vault.aes"
    if os.path.exists(vaultFile):
        try:
            with open(vaultFile, "w") as w:
                pass
            os.remove(vaultFile)
            print("[+] Vault successfully deleted.")
        except PermissionError:
            print("[!] You do not have permission to delete this vault file.")
        except Exception as e:
            print(f"[!] Error occured while deleting vault file: {e}")
    else:
        print("[!] No vault file exists, unless it was moved out of the Ncrypt directory.")

def writeVault():
    args = parse()
    path = args.file
    passwd = args.key
    vaultFile = "vault.aes"

    def decryptVault(key):
        with open(vaultFile, "rb") as readVault:
            ciphertxtData = readVault.read()
        iv = ciphertxtData[:AES.block_size]
        ciphertext = ciphertxtData[AES.block_size:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        try:
            plaintxtData = unpad(cipher.decrypt(ciphertext), AES.block_size)
            return plaintxtData.decode("utf-8")
        except ValueError:
            print("[!] Error decrypting the vault file. Likely incorrect master key.")

    def writeData(original, appended):
        try:
            with open(vaultFile, "w") as writeVault:
                writeVault.write(original)
                writeVault.write(f"\n{appended}")
        except Exception as e:
            print(f"[!] Error occured while writing plaintext data to the vault file: {e}")

    def encryptVault(key):
        iv = get_random_bytes(AES.block_size)
        with open(vaultFile, "rb") as readVault:
            plainData = readVault.read()
            cipher = AES.new(key, AES.MODE_CBC, iv)
            padded = pad(plainData, AES.block_size)
            ciphertext = cipher.encrypt(padded)
        with open(vaultFile, "wb") as writeVault:
            writeVault.write(iv + ciphertext)
            print("[+] Path and key saved successfully.")

    if os.path.exists(vaultFile):
        key = deriveKey(getpass.getpass("[>] Enter your master key: "))
        plaintxt = decryptVault(key)
        newData = (f"{path}:{passwd}")
        writeData(plaintxt,newData)
        encryptVault(key)
    else:
        print("[!] No vault file exists. Cannot save path/key pair.")

args = parse()
if not args.hashfile and not args.encrypt and not args.decrypt and not args.makevault and not args.readvault and not args.clearvault:
    print("\n[!] No valid operation specified. Must specify whether encrypting, decrypting, hashing, or creating a vault.")
elif args.hashfile or args.encrypt or args.decrypt or args.makevault or args.readvault or args.clearvault:
    trueCount = 0
    for i in (args.hashfile, args.encrypt, args.decrypt, args.makevault, args.readvault, args.clearvault):
        if i == True:
            trueCount += 1
    if trueCount > 1:
        print("\n[!] Cannot specify more than one operation. (Encrypt, Decrypt, Hash, Make Vault)")
    else:
        if args.encrypt:
            if not args.key == None:
                if not args.file == None:
                    encrypt()
                    if args.savevault:
                        writeVault()
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
        elif args.makevault:
            makeVault()
        elif args.readvault:
            readVault()
        elif args.clearvault:
            clearVault()