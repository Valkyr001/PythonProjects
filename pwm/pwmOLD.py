#Password management multi-tool
#Working modules as of 11/8/2024: Analysis, Storage, Hashing

import tkinter as tk
import re
from ip import insecurePhrases as ip
import random
import hashlib
import os
import datetime
import requests

root = tk.Tk()
#width x height
root.geometry("550x350")
root.title("pwm")
root.resizable(False,False)

pwd_var = tk.StringVar()

def strCheck():
    string = pwd_var.get()
    length = False
    uppercase = False
    lowercase = False
    nums = False
    specials = False
    ipDetected = False
    chks = 0
    ips = []
    crit = []

    if string != "":
        if re.match(r"^.{10,}$",string):
            length = True
            crit.append(True)
        if re.search(r"[A-Z]",string):
            uppercase = True
            crit.append(True)
        if re.search(r"[a-z]",string):
            lowercase = True
            crit.append(True)
        if re.search(r"[0-9]",string):
            nums = True
            crit.append(True)
        if re.search(r"[!@#$%^&*()]",string):
            specials = True
            crit.append(True)

        output("\n--------------------------------")
        output("\nResults: ")

        for i in crit:
            if i == True:
                chks += 1

        for word in ip:
            if word in string:
                ipDetected = True
                ips.append(str(word))

        if chks == 5 and ipDetected == False:
            output("\nPassword Strength: High")
        elif chks == 5 and ipDetected == True:
            output("\nPassword Strength: Medium")
        elif chks >= 3:
            output("\nPassword Strength: Medium")
        else:
            output("\nPassword Strength: Low")   
        
        output("\nRecommendations: ")

        if ipDetected == True:
            output("\nRemove the following insecure / easily guessable phrases from your password: ")
            for item in ips:
                output(item)
        
        hibpAPI(string)

        if length == False:
            output("\nIncrease password length to atleast 10 characters")
        if uppercase == False:
            output("\nAdd uppercase characters to your password")
        if lowercase == False:
            output("\nAdd lowercase characters to your password")
        if nums == False:
            output("\nAdd numbers to your password.")
        if specials == False:
            output("\nAdd special characters to your password such as '!' or '%'")
    else:
        output("\nNo input detected. Cannot analyze.")

def hibpAPI(passwrd):
    sha1 = hashlib.sha1(passwrd.encode("utf-8")).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/" + str(prefix)
    response = requests.get(url)

    if response.status_code == 200:
        pwned = response.text.splitlines()
        for line in pwned:
            stored_suffix, count = line.split(':')
            if stored_suffix == suffix:
                output("\nHIBP Results:")
                output("\nPASSWORD FOUND - pwned " + count + " times.")
                return True
        output("\npwd not found")
        return False
    else:
        output(f"Error: unable to check password. HTTP Code: " + response.status_code)

def output(text):
    out.config(state='normal')
    out.insert(tk.END, str(text))
    out.yview(tk.END)
    out.config(state='disabled')

def clear():
    out.config(state='normal')
    out.delete("1.0", tk.END)
    out.config(state="disabled")

def storeHashFile():
    timestamp = datetime.datetime.now()

    string = pwd_var.get()

    if string != "":
        #Create the pwm directory if not already existant
        dirName = "storage/hash"
        os.makedirs(dirName, exist_ok=True)

        uid = random.randint(10000,99999)

        salted = (str(uid) + string)
        
        hashstr = hashlib.sha512(salted.encode())
        hex = hashstr.hexdigest()

        f = open("storage/hash/pass" + str(uid) + ".txt","a")
        f.write(str(timestamp))
        f.write("\n" + hex)
        f.close()
        output("\nPassword stored as salted hash (SHA512) at pwm/storage/hash/pass" + str(uid) + ".txt")
    else:
        output("\nNo input detected, cannot store password.")

def storePlaintext():
    timestamp = datetime.datetime.now()

    string = pwd_var.get()

    if string != "":
        #Create the pwm directory if not already existant
        dirName = "storage/plaintxt"
        os.makedirs(dirName, exist_ok=True)

        uid = random.randint(1000,9999)

        f = open("storage/plaintxt/pass" + str(uid) + ".txt","a")
        f.write(str(timestamp))
        f.write("\n" + string)
        f.close()
        output("\nPassword stored in plaintext at storage/plaintxt/pass" + str(uid) + ".txt")
    else:
        output("\nNo input detected, cannot store password.")

header = tk.Label(root, text="Input your password: ")
header.pack(expand=True)

pwd_in = tk.Entry(root, width=40, textvariable=pwd_var)
pwd_in.pack(expand=True)

button_frame = tk.Frame(root)
button_frame.pack(fill='x', padx=10, pady=10)

output_header = tk.Label(root, text="Output: ")
output_header.pack()

submit = tk.Button(button_frame, text="Analyze",width=20,command=strCheck)
submit.pack(side="left", expand=True)

hash = tk.Button(button_frame, text="Store as hash",width=20,command=storeHashFile)
hash.pack(side="left", expand=True)

plain = tk.Button(button_frame, text="Store as plaintext",width=20,command=storePlaintext)
plain.pack(side="left", expand=True)

out = tk.Text(root, height=10, width=70)
out.pack()
out.config(state='disabled')

clearout = tk.Button(root,text="Clear Output",width=20,command=clear)
clearout.pack(expand=True,pady=5)

root.mainloop()