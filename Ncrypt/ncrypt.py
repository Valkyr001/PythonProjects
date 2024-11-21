#Python script for encrypting specified files.
#Includes option to create an encrypted vault file to store passwords.

#Header Key:
#[+] = Successful Operation
#[!] = Unsuccessful Operation/Error
#[*] = Information
#[>] = User input

#libraries
import hashlib
import os
import argparse
import getpass
import datetime
import re
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

#parser
def parse():
    parser = argparse.ArgumentParser(description="Python script for encrypting and decrypting files using AES-256.")
    parser.add_argument("-e", "--encrypt", help="Encrypt the specified target file. -f option required.", action="store_true")
    parser.add_argument("-d", "--decrypt", help="Decrypt the specified target file. -f option required.", action="store_true")
    parser.add_argument("-s", "--hash", help="Generate SHA-256 hash of the specified file. -f option required.", action="store_true")
    parser.add_argument("-f", "--file", type=str, help="Specify the target file.")
    parser.add_argument("-wV", "--writevault", help="Store the passkey used in the current operation in the vault file.", action="store_true")
    parser.add_argument("-mV", "--makevault", help="Create a new vault file.", action="store_true")
    parser.add_argument("-rV", "--readvault", help="Prints the decrypted contents of the vault file.", action="store_true")
    parser.add_argument("-cV", "--clearvault", help="Delete the vault file.", action="store_true")
    return parser.parse_args()

#derive SHA-256 from key
def derive(key):
    sha256 = hashlib.sha256(key.encode()).digest()
    return sha256

#remove extension from file path
def rmExt(path):
    root, ext = os.path.splitext(path)
    return root

#encrypt the target file, save to vault if specified
def encrypt(save):
    args = parse()
    path = args.file
    iv = get_random_bytes(AES.block_size)
    plainkey1 = getpass.getpass("\n[>] Create an encryption key (password): ")
    plainkey2 = getpass.getpass("[>] Re-enter the encryption key: ")

    def writeVault(plainkey):
        vault = input("\n[>] Enter the name of the vault to save to: ")
        masterKey = derive(getpass.getpass("[>] Enter your master key: "))

        def decryptVault(key):
            with open(vault, "rb") as readVault:
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
                with open(vault, "w") as writeVault:
                    writeVault.write(original)
                    writeVault.write(f"\n{appended}")
            except Exception as e:
                print(f"[!] Error occured while writing plaintext data to the vault file: {e}")

        def encryptVault(key):
            iv = get_random_bytes(AES.block_size)
            with open(vault, "rb") as readVault:
                plainData = readVault.read()
            cipher = AES.new(key, AES.MODE_CBC, iv)
            padded = pad(plainData, AES.block_size)
            ciphertext = cipher.encrypt(padded)
            with open(vault, "wb") as writeVault:
                writeVault.write(iv + ciphertext)
            print("[+] Path and key saved successfully.")

        if os.path.exists(vault):
            plaintxt = decryptVault(masterKey)
            fullPath = os.path.abspath(path)
            newData = (f"{fullPath}:{plainkey}")
            writeData(plaintxt,newData)
            encryptVault(masterKey)
        else:
            print("[!] No vault file exists. Cannot save path/key pair.")

    if plainkey1 == plainkey2:
        keyhash = derive(plainkey1)
        print("\n[*] Warning: This operation will completely overwrite the original file's contents.")
        print("[*] Ensure that the encryption key is stored safely to avoid permanant data loss. Consider using -sV")
        print("[*] The file extension will be converted to .aes")
        confirm = input("\n[>] Do you wish to proceed? (y/n): ")
        if confirm.lower() == "y":
            try:
                with open(path, "rb") as rf1:
                    data = rf1.read()
            except FileNotFoundError:
                print("[!] Specified file could not be found.")
                quit()
            except PermissionError:
                print("[!] You do not have permission to read this file.")
                quit()
            cipher = AES.new(keyhash, AES.MODE_CBC, iv)
            padded = pad(data, AES.block_size)
            encrypted = cipher.encrypt(padded)
            try:
                with open(path, "wb") as wf1:
                    wf1.write(iv + encrypted)
            except PermissionError:
                print("[!] You do not have permission to write to the target file.")
                quit()
            cutExt = rmExt(path)
            newPath = cutExt + ".aes"
            fullPath = os.path.abspath(newPath)
            os.rename(path, newPath)
            print(f"[+] File encrypted successfully and saved at {fullPath}")

            if save:
                writeVault(plainkey1)
            else:
                return
        elif confirm.lower() == "n":
            print("[*] Exiting.")
            quit()
        else:
            print("[!] Invalid input.")
            quit()
    else:
        print("[!] Encryption keys do not match.")
        quit()

#decrypt the specified file
def decrypt():
    args = parse()
    path = args.file
    key = derive(getpass.getpass("\n[>] Enter your decryption key: "))
    try:
        with open(path, "rb") as rf1:
            data = rf1.read()
            iv = data[:AES.block_size]
            ciphertext = data[AES.block_size:]
    except FileNotFoundError:
        print("[!] The specified file could not be found. Maybe forgot to add .aes?")
        quit()
    except PermissionError:
        print("[!] You do not have permission to read the target file.")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ext = input("[>] Specify the file type to save the decrypted file as (.txt, .png, .log, etc): ")
    if re.match(r"(\.[a-zA-Z]{3,4})", ext):
        try:
            decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
        except ValueError:
            print("[!] Failed to decrypt the file contents. Invalid key or corrupt data.")
        try:
            with open(path, "wb") as wf1:
                wf1.write(decrypted)
        except PermissionError:
            print("[!] You do not have permission to write to the target file.")
            quit()
        cutExt = rmExt(path)
        newPath = cutExt + ext
        fullPath = os.path.abspath(newPath)
        os.rename(path, newPath)
        print(f"[+] File decrypted successfully and saved as {fullPath}")
    else:
        print("[!] Invalid file extension.")
        quit()

def hash():
    args = parse()
    file = args.file
    try:
        with open(file, "r") as rf1:
            data = rf1.read()
            sha256 = hashlib.sha256(data.encode()).hexdigest()
            print(f"\n[+] SHA-256: {sha256}")
    except FileNotFoundError:
        print("[!] The specified file could not be found.")
    except PermissionError:
        print("[!] You do not have permission to read the target file.")

def makeVault():
    vault = input("[>] Create a name for your vault (.aes extension is added automatically): ") + ".aes"
    if os.path.exists(vault):
        print("\n[!] A vault with this name already exists.")
        return
    else:
        masterKey1 = getpass.getpass("\n[i] Create a master key to encrypt/decrypt the vault file: ")
        masterKey2 = getpass.getpass("[i] Re-enter your new master key: ")
        if masterKey1 == masterKey2:
            iv = get_random_bytes(AES.block_size)
            key = derive(masterKey1)
            timestamp = datetime.datetime.now()
            with open(vault, "w") as wf1:
                wf1.write(f"Vault Created: {timestamp} Format: <FILEPATH>:<PASSWORD>")
            with open(vault, "rb") as rf1:
                data = rf1.read()

            cipher = AES.new(key, AES.MODE_CBC, iv)
            padded = pad(data, AES.block_size)
            encrypted = cipher.encrypt(padded)
            try:
                with open(vault, "wb") as wf2:
                    wf2.write(iv + encrypted)
                print(f"[+] Vault created successfully. Location: {os.path.abspath(vault)}")
            except ValueError:
                print("[!] Error occured while creating the vault file.")
                print(f"[!] Error Details: {ValueError}")

        else:
            print("[!] Master keys do not match. Exiting.")
            return

def readVault():
    vault = input("[>] Enter the name of the vault to read: ")
    if os.path.exists(vault):
        masterKey = getpass.getpass("[>] Enter your master key: ")
        key = derive(masterKey)
        with open(vault, "rb") as rf1:
            getData = rf1.read()

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
        print("\n[!] The specified vault file could not be found.")

def clearVault():
    vault = input("[>] Enter the name of the vault to delete: ")
    if os.path.exists(vault):
        try:
            with open(vault, "w") as wf1:
                pass
            os.remove(vault)
            print("[+] Vault successfully deleted.")
        except PermissionError:
            print("[!] You do not have permission to delete this vault file.")
        except Exception as e:
            print(f"[!] Error occured while deleting vault file: {e}")
    else:
        print("[!] Could not find the specified file name. Did you add .aes?")

args = parse()
allopts = (
    args.encrypt,
    args.decrypt,
    args.hash,
    args.file,
    args.writevault,
    args.makevault,
    args.readvault,
    args.clearvault
)
count = 0
for i in allopts:
    if i:
        count += 1
if count == 0:
    print("[!] No arguments specified.")
else:
    count = 0
    for i in allopts[:2]:
        if i:
            count += 1
    if count > 1:
        print("[!] Cannot specify more than one of: (Encrypt, Decrypt, Hash)")
        quit()
    if args.encrypt:
        if not args.file == None:
            if args.writevault:
                encrypt(True)
            if not args.writevault:
                encrypt(False)
        else:
            print("[!] No target file specified.")
    elif args.decrypt:
        if not args.file == None:
            decrypt()
        else:
            print("[!] No target file specified.")
    elif args.hash:
        if not args.file == None:
            hash()
        else:
            print("[!] No target file specified.")
    if not (args.encrypt or args.decrypt or args.hash) and args.file:
        print("\n[!] No operation specified (Encrypt, Decrypt, Hash).")
    count = 0
    for i in (args.makevault, args.clearvault, args.readvault):
        if i:
            count += 1
    if i > 1:
        print("[!] Cannot specify more than one of: (-mV, -cV, -rV) in one operation.")
    else:
        if args.makevault:
            makeVault()
        elif args.clearvault:
            clearVault()
        elif args.readvault:
            readVault()