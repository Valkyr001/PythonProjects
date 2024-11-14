#Password management multi-tool.
#Can analyze a given password and output recommendations and weaknesses.
#Utilizes the Have I Been Pwned API to check the password against databreaches.

#This version of pwm handles user-interaction through the command prompt/terminal.

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
import requests
import argparse
import shutil

sysVer = "1.0.0" #version

def argument_parse():
    parser = argparse.ArgumentParser(description="PWM (PassWord Manager) in a python script capable of analyzing and storing user-supplied passwords.")
    parser.add_argument("password", nargs="?", help="Input the password for analysis/storage or the filename of a saved file to read/delete.")
    parser.add_argument("-n", "--noanalysis", help="Do not analyze the password. Useful for just storing the password without analyzing it.",action="store_false")
    parser.add_argument("-p", "--plaintext", help="Store the password in plaintext",action="store_true")
    parser.add_argument("-s", "--sha256", help="Store the password as a hash (SHA256)",action="store_true")
    #parser.add_argument("-e", "--encrypt", help="Stores password encrypted",action="store_true")
    #parser.add_argument("-r", "--read", help="Read a stored password.",action="store_true")
    parser.add_argument("-a", "--noapi", help="Disables the HaveIBeenPwned API check in case using offline. Script will still work if not used but you will see an error in the output.",action="store_true")
    parser.add_argument("-c", "--clearvault", help="Deletes the vault directory and all data inside of it.", action="store_true")
    parser.add_argument("-d", "--delete", help="Deletes the specified filename (must be inside vault directory, write in place of password)",action="store_true")
    parser.add_argument("-v", "--version", help="Output the script version", action="store_true")
    parser.add_argument("-i", "--icons", help="Print out the meaning of each line icon prefix.",action="store_true")

    return parser.parse_args()

#main function
def main():
    #main function variables
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
            if re.match(r"^.{10,}$",string):
                checks["length"] = True
            if re.search(r"[A-Z]",string):
                checks["uppercase"] = True
            if re.search(r"[a-z]",string):
                checks["lowercase"] = True
            if re.search(r"[0-9]",string):
                checks["nums"] = True
            if re.search(r"[!@#$%^&*()]",string):
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

#handles storage of password in plaintext (-p option)
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

def clearVault():
    try:
        shutil.rmtree("vault")
        print("\n[+] Vault Cleared.")
    except Exception:
        print(f"\n[*] Error: {Exception}")

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

def icons():
    print("\n[>] - Header")
    print("[+] - Success/Check Passed")
    print("[!] - Alert/Check Failed")
    print("[i] - Informational")
    print("[*] - Critical Error")
        
args = argument_parse()
if args.clearvault == False and args.delete == False and args.version == False and args.icons == False:
    if args.password == None:
        print("\n[!] Error: No input provided.")
    else:
        if args.noanalysis == True:
            main()
        if args.plaintext == True:
            savePlaintext()
        if args.sha256 == True:
            saveHashed()
else:
    if args.clearvault == True:
        clearVault()
    if args.delete == True:
        deleteFile()
    if args.version == True:
        print(f"\npwm.py version: {sysVer}")
    if args.icons == True:
        icons()