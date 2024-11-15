#Password management multi-tool.
#Can analyze a given password and output recommendations and weaknesses.
#Utilizes the Have I Been Pwned API to check the password against databreaches.
#Can store passwords in plaintext, SHA256, or AES-256.

#Output notation:
#[>] Header
#[+] Check Passed/Successful Operation
#[!] Check Failed/Alert
#[i] Information
#[*] Critical Error

#libraries
import re
from ip import insecurePhrases as phrases
import hashlib
import os
import datetime
import requests #must be downloaded
import argparse
import shutil
from Crypto.Cipher import AES               #must be downloaded
from Crypto.Random import get_random_bytes  #must be downloaded
from Crypto.Util.Padding import pad, unpad  #must be downloaded

sysVer = "1.1.0" #version

#create command-line arguments to modify script behavior
def argument_parse():
    parser = argparse.ArgumentParser(description="PWM (PassWord Manager) in a python script capable of analyzing and storing user-supplied passwords as plaintext, hashed using SHA-256, or encrypted using AES-256.")
    parser.add_argument("password", nargs="?", help="Input the password for analysis/storage or the filename of a saved file to read/delete.")
    parser.add_argument("-n", "--noanalysis", help="Do not analyze the password. Useful for just storing the password without analyzing it.",action="store_false")
    parser.add_argument("-p", "--plaintext", help="Store the password in plaintext",action="store_true")
    parser.add_argument("-s", "--sha256", help="Store the password as a hash (SHA-256)",action="store_true")
    parser.add_argument("-r", "--read", help="Read the contents of a password file. This will read the raw data from the file, use -u for encrypted files. Hashed passwords cannot be directly retrieved.", action="store_true")
    parser.add_argument("-o", "--readvault", help="List the contents of the vault.",action="store_true")
    parser.add_argument("-e", "--encrypt", help="Stores password encrypted (AES-256)",action="store_true")
    parser.add_argument("-u", "--decrypt", help="Decrypt an encrypted key. Must be in the pwm/vault/ directory.",action="store_true")
    parser.add_argument("-a", "--noapi", help="Disables the HaveIBeenPwned API check in case using offline. Script will still work if not used but you will see an error in the output.",action="store_true")
    parser.add_argument("-c", "--clearvault", help="Deletes the vault directory and all data inside of it.", action="store_true")
    parser.add_argument("-d", "--delete", help="Deletes the specified filename (must be inside vault directory, write in place of password)",action="store_true")
    parser.add_argument("-v", "--version", help="Output the script version", action="store_true")
    parser.add_argument("-i", "--icons", help="Print out the meaning of each line icon prefix.",action="store_true")

    return parser.parse_args()

#main function
def main():
    args = argument_parse()
    password = args.password
    phraseList = []

    checks = {
        "length":False,
        "uppercase":False,
        "lowercase":False,
        "nums":False,
        "specials":False,
        "phrase":False
    }

    #check password against simple characteristics with RegEx
    def simpleChecks(string):
        if string != "":
            if re.match(r"^.{10,}$",string):    #checks for minimum length
                checks["length"] = True
            if re.search(r"[A-Z]",string):      #checks for uppercase letters
                checks["uppercase"] = True
            if re.search(r"[a-z]",string):      #checks for lowercase letters
                checks["lowercase"] = True
            if re.search(r"[0-9]",string):      #checks for numbers
                checks["nums"] = True
            if re.search(r"[!@#$%^&*()]",string):   #checks for at least one special character
                checks["specials"] = True
        else:
            print("[*] Invalid password string input")

        if checks["length"] == False:
            print("[i] Increase the length of your password.")
        if checks["uppercase"] == False:
            print("[i] Add uppercase characters to your password.")
        if checks["lowercase"] == False:
            print("[i] Add lowercase characters to your password.")
        if checks["nums"] == False:
            print("[i] Add numbers to your password.")
        if checks["specials"] == False:
            print("[i] Add special characters to your password.")

    #check password against known data breaches with HIBP API
    def apiCheck(string):
        if args.noapi == False:
            sha1 = hashlib.sha1(string.encode("utf-8")).hexdigest().upper()
            prefix = sha1[:5]
            suffix = sha1[5:]
            url = f"https://api.pwnedpasswords.com/range/" + str(prefix)
            response = requests.get(url)

            print("\n[>] HaveIBeenPwned API Results:")

            if response.status_code == 200:
                pwned = response.text.splitlines()
                for line in pwned:
                    stored_suffix, count = line.split(":")
                    if stored_suffix == suffix:
                        print(f"[!] Password has been pwned {count} times.")
                        return True
                print("[+] Password not found in any data breaches.")
                return False           
            else:
                print(f"[*] Error encountered while attempting to reach API. HTTP Code: {response.status_code}")
        else:
            print("[i] HIBP API disabled. Skipping data breach check.")
            pass
    
    #check the password for any of the phrases from ip.py
    def checkPhrases(string):
        for word in phrases:
            if word in string:
                phrase = True
                phraseList.append(str(word))
        try:
            if phrase == True:
                for i in phraseList:
                    print(f"[i] Remove the word or phrase: '{i}'")
        except UnboundLocalError:
            pass

    #run through methods, result output is handled within each method
    if password != "":
        print("\n[>>>] RESULTS [<<<]\n")
        simpleChecks(password)
        checkPhrases(password)
        apiCheck(password)

#handles storage of password in plaintext
def savePlaintext():
    args = argument_parse()
    string = args.password
    timestamp = datetime.datetime.now()
    path = "vault"

    if string != None:
        filename = input("\n[i] Specify a file name for plaintext output (no extensions): ")
        os.makedirs(path, exist_ok=True)
        f = open(f"{path}/{filename}.txt","a")
        f.write(str(timestamp))
        f.write(f"\n{string}")
        f.close()
        print(f"[+] Password stored in plaintext at {path}/{filename}.txt")
        print(f"[i] Use caution when storing credentials insecurely such as in plaintext.")
    else:
        print("[!] No input detected. Cannot store password.")

#handles storage of password in SHA-256
def saveHashed():
    args = argument_parse()
    string = args.password
    timestamp = datetime.datetime.now()
    path = "vault"
    filename = input("\n[i] Specify a file name for SHA256 output (no extensions): ")

    if string != "":
        os.makedirs(path, exist_ok=True)
        hash = hashlib.sha256(string.encode()).hexdigest()

        f = open(f"{path}/{filename}.txt","a")
        f.write(str(timestamp))
        f.write("\n" + str(hash))
        f.close()
        print(f"[+] Password stored as SHA256 at {path}/{filename}.txt")
    else:
        print("[!] No input detected. Cannot store password.")

#convert encryption passphrase into SHA-256 to pass to AES as encryption key
def deriveKey(passphrase):
    sha256 = hashlib.sha256(passphrase.encode()).digest()
    return sha256

#encrypt the specified file
def encrypt():
    args = argument_parse()
    path = "vault"
    iv = get_random_bytes(AES.block_size)
    password = args.password
    
    filename = input("\n[i] Specify a file name for the encrypted password: ")
    plaintextKey = input("[i] Specify the key (password) to encrypt/decrypt the password: ")
    key = deriveKey(plaintextKey)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(password.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded_data)

    os.makedirs(path, exist_ok=True)
    f = open(f"{path}/{filename}.enc","wb")
    f.write(iv + ciphertext)
    f.close()
    print(f"[+] Password stored at pwm/{path}/{filename}.enc as ciphertext (AES256).")

#decrypt specified file
def decrypt():
    filename = input("\n[i] Specify the filename to decrypt: ")
    plaintextKey = input("[i] Specify the encryption key (password): ")
    key = deriveKey(plaintextKey)
    with open(f"vault/{filename}.enc", "rb") as target:
        encryptedData = target.read()

    iv = encryptedData[:AES.block_size]
    ciphertext = encryptedData[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        decryptedData = unpad(cipher.decrypt(ciphertext), AES.block_size)
        print(f"[i] Decrypted Key: {decryptedData.decode("utf-8")}")
    except ValueError:
        print("[!] Decryption Failed: Invalid key or corrupted data.")

#read specified file, should be used only will plaintext or hashed files
def read():
    filename = input("\n[i] Specify the password filename to read: ")
    try:
        with open(f"vault/{filename}.txt", "r") as file:
            contents = file.readlines()
            password = contents[1].strip()
            print(f"[+] {password}")
    except FileNotFoundError:
        print("[!] Invalid file name or file type.")

def readVault():
    directory = "/vault"
    try:
        files = os.listdir("vault")
        print("\n[>] Vault Contents:\n")
        for file in files:
            file_path = os.path.join("vault",file)
            if os.path.isfile(file_path):
                print(f"[+] {file}")
    except FileNotFoundError:
        print(f"\n[!] The directory '{directory}' does not exist.")
    except PermissionError:
        print(f"\n[!] Permission denied to access the directory {directory}")
    except Exception as e:
        print(f"\n[*] Error accessing {directory}: {e}")

#delete the vault directory and all of its contents
def clearVault():
    try:
        shutil.rmtree("vault")
        print("\n[+] Vault Cleared.")
    except Exception:
        print(f"\n[*] Error: {Exception}")

#delete a specific password file
def deleteFile():
    args = argument_parse()
    try:
        os.remove(f"vault/{args.password}.txt")
        print(f"\n[+] vault/{args.password}.txt removed successfully.")
    except FileNotFoundError:
        print("\n[!] Error: The file could not be found.")
    except PermissionError:
        print(f"\n[!] Error: You do not have permission to delete vault/{args.password}.txt")
    except OSError as e:
        print(f"\n[*] Error: {e.strerror}")

#print the definitions for each of the line prefixes
def icons():
    print("\n[>] - Header")
    print("[+] - Success/Check Passed")
    print("[!] - Alert/Check Failed")
    print("[i] - Informational")
    print("[*] - Critical Error")

#parse arguments and run script
args = argument_parse()
if args.clearvault == False and args.delete == False and args.version == False and args.icons == False and args.decrypt == False and args.read == False and args.readvault == False:
    if args.password == None:
        print("\n[!] Error: No input provided.")
    else:
        if args.noanalysis == True:
            main()
        if args.plaintext == True:
            savePlaintext()
        if args.sha256 == True:
            saveHashed()
        if args.encrypt == True:
            encrypt()
else:
    if args.clearvault == True:
        clearVault()
    if args.delete == True:
        deleteFile()
    if args.version == True:
        print(f"\npwm.py version: {sysVer}")
    if args.icons == True:
        icons()
    if args.decrypt == True:
        decrypt()
    if args.read == True:
        read()
    if args.readvault == True:
        readVault()