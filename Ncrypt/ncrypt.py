#Python script for encrypting specified files.
#Optional encrypted vault for storing passwords included.

#Header Key:
#[+] = Successful Operation
#[!] = Unsuccessful Operation
#[*] = Information
#[>] = User input
#[!!!] - Critical/Unknown Error (Exception Provided)

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
    parser.add_argument("-e", "--encrypt", help="Encrypt the specified target file. -f and -k options required.", action="store_true")
    parser.add_argument("-d", "--decrypt", help="Decrypt the specified target file. -f and -k options required.", action="store_true")
    parser.add_argument("-s", "--hashfile", help="Generate SHA-256 hash of the specified file. -f option required.", action="store_true")
    parser.add_argument("-k", "--key", type=str, help="Specify the key/password to use for the current operation.")
    parser.add_argument("-f", "--file", type=str, help="Specify the target file. Use full path.")
    parser.add_argument("-sV", "--savevault", help="Store the passkey used in the current operation in the vault file. -k must be included.", action="store_true")
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
        print("[!] Error occured while generating SHA-256 hash of plaintext key.")

#cut extensions
def cutExt(path):
    root, ext = os.path.splitext(path)
    return root

#encrypt file
def encrypt():
    args = parse()
    path = args.file
    key = derive(args.key)
    iv = get_random_bytes(AES.block_size)

    print("\n[*] Warning: This operation will completely overwrite the contents of the target file with the encrypted version.")
    print("[*] To avoid permanant data loss ensure that the encryption key is stored securely. Consider using -sV")
    print("[*] The target file will be converted to .aes format.")
    confirm = input("\n[>] Do you wish to proceed? (y/n)")

    if confirm.lower() in ["y","n"]:
        if confirm.lower() == "y":
            try:
                with open(path, "rb") as pf1:
                    plaintxt = pf1.read()
            except FileNotFoundError:
                print("[!] Unable to read target file: File Not Found.")
            except PermissionError:
                print("[!] Unable to read the target file, you do not have permission to read the file.")
            except Exception as e0:
                print(f"[!!!] Unknown error occured while attempting to read target file: {e0}")
            try:
                cipher = AES.new(key, AES.MODE_CBC, iv)
                padded = pad(plaintxt, AES.block_size)
                ciphertxt = cipher.encrypt(padded)
            except ValueError:
                print("[!] An error occured while encrypting the binary data.")
            except Exception as e1:
                print(f"[!!!] Unknown error occured while attempting to encrypt binary data: {e1}")
            try:
                with open(path, "wb") as ef1:
                    ef1.write(iv + ciphertxt)
            except ValueError:
                print("[!] Error occured while encrypting the file contents.")
            except Exception as e2:
                print(f"[!!!] An unknown error occured while writing to the target file: {e2}")
            try:
                cutExt = cutExt(path)
                newPath = cutExt + ".aes"
                os.rename(path, newPath)
            except PermissionError:
                print("[!] An error occured while attempting to reformat the target file to AES. You do not have permission to perform this action.")
            except FileNotFoundError:
                print("[!] An error occured while attempting to reformat the target file. File Not Found.")
            print(f"[+] File encrypted as saved as {newPath}")

        elif confirm.lower() == "n":
            print("[*] Closing Program...")
            return
    else:
        print("[!] Unexpected or invalid input provided.")
        return

#decrypt file   
def decrypt():
    args = parse()
    path = args.file
    key = derive(args.key)
    try:
        with open(path, "rb") as ef1:
            encryptedData = ef1.read()
    except FileNotFoundError as fnf0:
        print("[!] Unable to locate target file.")
    except PermissionError as permErr0:
        print("[!] You do not have permission to read the target file.")
    except Exception as e0:
        print(f"[!!!] Unknown error occured while attempting to read target file: {e0}")
    iv = encryptedData[:AES.block_size]
    ciphertext = encryptedData[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ext = input("[>] Specify the file extension to convert the target file to: ")
    if re.match(r"(\.[a-zA-Z]{3,4})", ext):
        try:
            plaintext = unpad(cipher.decrypt)
        except ValueError:
            print("[!] Unable to decrypt target file. Invalid key or corrupted data.")
        except Exception as e:
            print(f"[!!!] Unknown error occured while decrypting target file: {e}")

