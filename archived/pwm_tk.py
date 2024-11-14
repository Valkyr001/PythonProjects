#Password management multi-tool.
#Can analyze a given password and output recommendations and weaknesses.
#Utilizes the Have I Been Pwned API to check the password against databreaches.

#This version of pwm handles user interaction via the Tkinter library.

#Output notation:
#[>] Header
#[+] Check Passed
#[!] Check Failed/Alert
#[i] Information
#[*] Error Information

#modules
import tkinter as tk
import re
from ip import insecurePhrases as phrases
import random
import hashlib
import os
import datetime
import requests

#build tkinter window
root = tk.Tk()
root.geometry("550x350")
root.title("pwm")
root.resizable(False,False)

#user-inputted password
userinput = tk.StringVar()

#main
def main():
    #main function variable
    password = userinput.get()
    phraseList = []

    checks = {
        "length":False,
        "uppercase":False,
        "lowercase":False,
        "nums":False,
        "specials":False,
        "phrase":False
    }

    #subfunctions / methods

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
            output("\n[*] Invalid password string inputted")

        if checks["length"] == False:
            output("\n[i] Increase the length of your password.")
        if checks["uppercase"] == False:
            output("\n[i] Add uppercase characters to your password.")
        if checks["lowercase"] == False:
            output("\n[i] Add lowercase characters to your password.")
        if checks["nums"] == False:
            output("\n[i] Add numbers to your password.")
        if checks["specials"] == False:
            output("\n[i] Add special characters to your password.")

    #check password against known data breaches with HIBP API
    def apiCheck(string):
        sha1 = hashlib.sha1(string.encode("utf-8")).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]
        url = f"https://api.pwnedpasswords.com/range/" + str(prefix)
        response = requests.get(url)

        output("\n[>] HaveIBeenPwned API Results:")

        if response.status_code == 200:
            pwned = response.text.splitlines()
            for line in pwned:
                stored_suffix, count = line.split(":")
                if stored_suffix == suffix:
                    output(f"\n[!] Password has been pwned {count} times.")
                    return True
            output("\n[+] Password not found in any data breaches.")
            return False           
        else:
            output(f"[*] Error encountered while attempting to reach API. HTTP Code: {response.status_code}")
    
    #check the password for any of the phrases from ip.py
    def checkPhrases(string):
        for word in phrases:
            if word in string:
                phrase = True
                phraseList.append(str(word))
        if phrase == True:
            for i in phraseList:
                output(f"\n[i] Remove the word or phrase: '{i}'")

    #run through subfunctions, result output is handled within each method
    if password != "":
        output("\n[>>>] RESULTS [<<<]")
        simpleChecks(password)
        checkPhrases(password)
        apiCheck(password)
    else:
        output("\n[!] Error analyzing password: no input detected.")

def output(text):
        out.config(state='normal')
        out.insert(tk.END, str(text))
        out.yview(tk.END)
        out.config(state='disabled')

def clear():
    out.config(state='normal')
    out.delete("1.0", tk.END)
    out.config(state="disabled")

def savePlaintext():
    string = userinput.get()
    timestamp = datetime.datetime.now()
    path = "pwm/vault"
    uid = random.randint(1000,9999)

    if string != "":
        os.makedirs(path, exist_ok=True)
        f = open(f"{path}/plaintxt{uid}.txt","a")
        f.write(str(timestamp))
        f.write(f"\n{string}")
        f.close()
        output(f"\n[i] Password stored in plaintext at {path}/plaintxt{uid}.txt")
    else:
        output("\n[!] No input detected. Cannot store password.")

def saveHashed():
    timestamp = datetime.datetime.now()
    string = userinput.get()
    path = "pwm/vault"
    uid = random.randint(1000,9999)

    if string != "":
        os.makedirs(path, exist_ok=True)
        hash = hashlib.sha256(string.encode()).hexdigest()

        f = open(f"{path}/hashed{uid}.txt","a")
        f.write(str(timestamp))
        f.write("\n" + str(hash))
        f.close()
        output(f"\n[i] Password stored as SHA256 at {path}/hashed{uid}.txt")
    else:
        output("\n[!] No input detected. Cannot store password.")
        
#tkinter widgets
header = tk.Label(root, text="Input your password: ")
header.pack(expand=True)

pwd_in = tk.Entry(root, width=40, textvariable=userinput)
pwd_in.pack(expand=True)

button_frame = tk.Frame(root)
button_frame.pack(fill='x', padx=10, pady=10)

output_header = tk.Label(root, text="Output: ")
output_header.pack()

submit = tk.Button(button_frame, text="Analyze",width=20,command=main)
submit.pack(side="left", expand=True)

hash = tk.Button(button_frame, text="Store as hash",width=20,command=saveHashed)
hash.pack(side="left", expand=True)

plain = tk.Button(button_frame, text="Store as plaintext",width=20,command=savePlaintext)
plain.pack(side="left", expand=True)

out = tk.Text(root, height=10, width=70)
out.pack()
out.config(state='disabled')

clearout = tk.Button(root,text="Clear Output",width=20,command=clear)
clearout.pack(expand=True,pady=5)

root.mainloop()

    
