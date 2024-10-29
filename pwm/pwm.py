#Password management multi-tool
#Working modules as of 10/29/2024: Analysis

import tkinter as tk
import re
from ip import insecurePhrases as ip

root = tk.Tk()
root.geometry("400x400")
root.title("pwm")

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

    print("Results: ")

    for i in crit:
        if i == True:
            chks += 1

    for word in ip:
        if word in string:
            ipDetected = True
            ips.append(str(word))

    if chks == 5 and ipDetected == False:
        print("Password Strength: High")
    elif chks == 5 and ipDetected == True:
        print("Password Strength: Medium")
    elif chks >= 3:
        print("Password Strength: Medium")
    else:
        print("Password Strength: Low")   
    
    print("\nRecommendations: ")

    if ipDetected == True:
        print("\nRemove the following phrases from your password: ")
        for item in ips:
            print(item)

    if length == False:
        print("\nIncrease password length to atleast 10 characters")
    if uppercase == False:
        print("Add uppercase characters to your password")
    if lowercase == False:
        print("Add lowercase characters to your password")
    if nums == False:
        print("Add numbers to your password.")
    if specials == False:
        print("Add special characters to your password such as '!' or '%'")

header = tk.Label(root, text="Input your password: ")
header.pack(expand=True)
pwd_in = tk.Entry(root, textvariable=pwd_var)
pwd_in.pack(expand=True)
submit = tk.Button(root, text="Submit",command=strCheck)
submit.pack(expand=True)


root.mainloop()