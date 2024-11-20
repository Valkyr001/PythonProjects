#Python script for encrypting specified files.
#Optional encrypted vault for storing passwords included.

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
    parser = argparse.ArgumentParser(description="Python script for encrypting and decrypting file with AES-256.")
    parser.add_argument("-e", "--encrypt", help="Encrypt the specified target file. -f option required.", action="store_true")
    parser.add_argument("-d", "--decrypt", help="Decrypt the specified target file. -f option required.", action="store_true")
    parser.add_argument("-s", "--hashfile", help="Generate SHA-256 hash of the specified file. -f option required.", action="store_true")
    parser.add_argument("-f", "--file", type=str, help="Specify the target file. Use full path.")
    parser.add_argument("-sV", "--savevault", help="Store the passkey used in the current operation in the vault file.", action="store_true")
    parser.add_argument("-mV", "--makevault", help="Create a new vault file.", action="store_true")
    parser.add_argument("-rV", "--readvault", help="Decrypts and prints the contents of the vault file.", action="store_true")
    parser.add_argument("-cV", "--clearvault", help="Delete the vault file.", action="store_true")
    return parser.parse_args()

#convert plaintext password to sha256 hash
def derive(string):
    try:
        sha256 = hashlib.sha256(string.encode()).digest()
        return sha256
    except Exception as e:
        print(f"[!] Error occured while generating SHA-256 hash of plaintext key: {e}")

#cut extensions
def cutExt(path):
    root, ext = os.path.splitext(path)
    return root

#encrypt file
def encrypt(wv):
    args = parse()
    path = args.file
    iv = get_random_bytes(AES.block_size)

    print("\n[*] Warning: This operation will completely overwrite the contents of the target file with the encrypted version.")
    print("[*] To avoid permanant data loss ensure that the encryption key is stored securely. Consider using -sV")
    print("[*] The target file will be converted to .aes format.")
    confirm = input("\n[>] Do you wish to proceed? (y/n)")

    if confirm in ["y", "n"]:
        if confirm == "y":
            k1 = getpass.getpass("[>] Create a password use as the encryption key: ")
            k2 = getpass.getpass("[>] Re-enter your key: ")
            if k1 == k2:
                key = derive(k1)
                try:
                    with open(path, "rb") as rb1:
                        data = rb1.read()
                    cipher = AES.new(key, AES.MODE_CBC, iv)
                    padded = pad(data, AES.block_size)
                    encrypted = cipher.encrypt(padded)
                    with open(path, "wb") as wb1:
                        wb1.write(iv + encrypted)
                    rmExt = cutExt(path)
                    newPath = rmExt + ".aes"
                    os.rename(path, newPath)
                    full = os.path.abspath(newPath)
                    print(f"[+] File encrypted successfully and saved as {full}")
                except ValueError:
                    print(f"[!] Unexpected error occured while encrypting file: {ValueError}")
                except PermissionError:
                    print("[!] You do not have permission to perform this operation.")
                except FileNotFoundError:
                    print("[!] The specified file could not be found.")
            else:
                print("[!] Passwords do not match. Encryption aborted.")
                quit()
                return
        elif confirm == "n":
            print("[+] Exiting.")
            return
    else:
        print("[!] Invalid input.")
        return
    
    def writeVault(plainkey):
        args = parse()
        path = args.file
        vault = "vault.aes"

        def decryptVault(mkey):
            with open(vault, "rb") as readVault:
                ciphertxtData = readVault.read()
            iv = ciphertxtData[:AES.block_size]
            ciphertext = ciphertxtData[AES.block_size:]
            cipher = AES.new(mkey, AES.MODE_CBC, iv)
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

        def encryptVault(mkey):
            iv = get_random_bytes(AES.block_size)
            with open(vault, "rb") as readVault:
                plainData = readVault.read()
                cipher = AES.new(mkey, AES.MODE_CBC, iv)
                padded = pad(plainData, AES.block_size)
                ciphertext = cipher.encrypt(padded)
            with open(vault, "wb") as writeVault:
                writeVault.write(iv + ciphertext)
                print("[+] Path and key saved successfully.")

        if os.path.exists(vault):
            mkey = getpass.getpass("[>] Enter your master key: ")
            keyHash = derive(mkey)
            plaintxt = decryptVault(keyHash)
            savePath = os.path.abspath(path)
            saveKey = plainkey.decode("utf-8")
            newData = (f"{savePath}:{saveKey}")
            writeData(plaintxt,newData)
            encryptVault(keyHash)
        else:
            print("[!] No vault file exists. Cannot save path/key pair.")

    if wv:
        writeVault(key)
    else:
        return

#decrypt file
def decrypt():
    args = parse()
    path = args.file
    key = derive(getpass.getpass("[>] Enter your passkey: "))
    try:
        with open(path, "rb") as rb1:
            data = rb1.read()
            iv = data[:AES.block_size]
            ciphertext = data[AES.block_size:]
    except FileNotFoundError:
        print("[!] Specifiled file could not be found.")
        return
    except PermissionError:
        print("[!] You do not have permission to perform this operation.")
        return
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        return
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ext = input("[>] Specify the file extension to convert the file to (required): ")
    if re.match(r"(\.[a-zA-Z]{3,4})", ext):
        try:
            decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
            with open(path, "wb") as wb1:
                wb1.write(decrypted)
            rmExt = cutExt(path)
            newPath = rmExt + ext
            os.rename(path, newPath)
            full = os.path.abspath(newPath)
            print(f"[+] File decrypted successfully and saved as {full}")
        except ValueError:
            print("[!] Decryption key is invalid or data is corrupted.")
            return
        except PermissionError:
            print("[!] You do not have permission to perform this operation.")
            return
        except FileNotFoundError:
            print("[!] The specified file cannot be found.")
            return
    else:
        print("[!] Invalid file extension. Decryption aborted.")
        return

#hash file
def hash():
    args = parse()
    file = args.file
    try:
        with open(file, "r") as rf:
            data = rf.read()
            sha256 = hashlib.sha256(data.encode()).hexdigest()
            print(f"[+] SHA-256: {sha256}")
    except FileNotFoundError:
        print("[!] The specified file could not be found.")
    except PermissionError:
        print("[!] You do not have permission to perform this operation.")

#create key storage vault
def makeVault():
    vault = "vault.aes"
    if os.path.exists(vault):
        full = os.path.abspath(vault)
        print(f"[!] Cannot create vault file because one already exists at: {full}")
        return
    else:
        mk1 = getpass.getpass("[>] Create a master key to access your vault: ")
        mk2 = getpass.getpass("[>] Re-enter the master key: ")
        if mk1 == mk2:
            iv = get_random_bytes(AES.block_size)
            key = derive(mk1)
            timestamp = datetime.datetime.now()
            with open(vault, "w") as wv1:
                wv1.write(f"Vault Initialized: {timestamp}")
            with open(vault, "rb") as rv1:
                data = rv1.read()
            cipher = AES.new(key, AES.MODE_CBC, iv)
            padded = pad(data, AES.block_size)
            encrypted = cipher.encrypt(padded)
            try:
                with open(vault, "wb") as wv2:
                    wv2.write(iv + encrypted)
                full = os.path.abspath(vault)
                print(f"[+] Vault created successfully. Location: {full}")
            except ValueError:
                print("[!] Unexpected error occured while creating vault file.")
                print(ValueError)
                return
        else:
            print("[!] Master keys do not match. Vault file was not created.")
            return

#read the contents of the vault file
def readVault():
    vault = "vault.aes"
    if os.path.exists(vault):
        mk = getpass.getpass("[>] Enter your master key to decrypt the vault: ")
        key = derive(mk)
        with open(vault, "rb") as rv1:
            data = rv1.read()
        iv = data[:AES.block_size]
        ciphertext = data[AES.block_size:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        try:
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
            print("[+] Vault Contents: ")
            print(plaintext.decode("utf-8"))
        except ValueError:
            print("[!] Error decrypting vault file. Invalid master key or corrupted data.")
    else:
        print("[!] No vault file exists or it cannot be located.")

#delete the vault fiel
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

args = parse()
#argument normalization and handling
counter = 0
for i in (args.encrypt, args.decrypt, args.hashfile, args.file, args.makevault, args.savevault, args.readvault, args.clearvault):
    if i:
        counter += 1
if counter == 0:
    print("[!] No arguments called. Exiting.")
counter = 0
for m in (args.encrypt, args.decrypt, args.hashfile):
    if m:
        counter += 1
if counter > 1:
    print("[!] Cannot specify more than one main operation (encrypt, decrypt, hash)")
else:
    if args.encrypt:
        if not args.file == None:
            if args.savevault:
                encrypt(True)
            elif not args.savevault:
                encrypt(False)
        else:
            print("[!] No target file specified.")
    elif args.decrypt:
        if not args.file == None:
            decrypt()
        else:
            print("[!] No target file specified.")
    elif args.hashfile:
        if not args.file == None:
            hash()
        else:
            print("[!] No target file specified.")
counter = 0
for s in (args.makevault, args.clearvault, args.readvault):
    if s:
        counter += 1
if counter > 1:
    print("[!] Cannot specify more than one (Make Vault, Read Vault, Clear Vault)")
else:
    if args.makevault:
        makeVault()
    elif args.clearvault:
        clearVault()
    elif args.readvault:
        readVault()



