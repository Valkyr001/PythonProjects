import time
import subprocess
import re
import random

#Random messages
msgs = {
    1:"testing out randint :)",
    2:"wonder if madi will ever see this",
    3:"def overlyComplicated()",
    4:"webvault coming soon",
    5:"the webvault thing is so cap XDDD"
}

#Functions
def returnError(stopcode):
    if stopcode == 1:
        print("Error 1: Invalid Scan Type")
    elif stopcode == 2:
        print("Error 2: Invalid IP Address for target host")
    elif stopcode == 3:
        print("Error 3: Invalid input on main menu option")
    elif stopcode == 4:
        print("Error 4: Invalid scan type selected")
    elif stopcode == 5:
        print("Error 5: Invalid input supplied for 'time limit'")
    elif stopcode == 6:
        print("Error 6: Invalid input supplied for 'count'")

def initScan(host,type,tlim=None,count=None):

    print("Scanning host: " + str(host))

    if type == "A":
        scan = subprocess.Popen("ping " + host)
    elif type == "B":
        scan = subprocess.Popen("ping -t " + host)
        time.sleep(int(tlim))
        print("Time limit (" + tlim + ") reached, terminating....")
        scan.terminate()
    elif type == "C":
        scan = subprocess.Popen("ping -c " + str(count) + " " + host)
    elif type == "D":
        print("\nEnter q to abort continuous scan.")
        scan = subprocess.Popen("ping -t " + host)
    elif type not in ["default","timed","counted","continuous"]:
        returnError(1)

    print(scan.stdout)

    while scan.poll() is None:
        close = input("")
        if close == "q":
            print("Scan terminated.")
            scan.terminate()

#Interaction
print("Starting icmpScan...")
print("Version: 1.0.0")
print("Author: benji")
num = random.randint(1,5)
print(msgs[num])

while True:
    print("\n Options: ")
    print("\n(A) Start a new scan")
    print("(B) End the program")
    opt1 = input("\nSelect: ")

    if opt1 == "A":
        host = input("Specify a target host (IPv4):  ")
        if re.match(r"^([1-9]|[1-9][0-9]|[1][0-9]{2}|[2][0-4][0-9]|[2][0-5]{2})\.([0]|[1-9]|[1-9][0-9]|[1][0-9]{2}|[2][0-4][0-9]|[2][0-5]{2})\.([0]|[1-9]|[1-9][0-9]|[1][0-9]{2}|[2][0-4][0-9]|[2][0-5]{2})\.([0]|[1-9]|[1-9][0-9]|[1][0-9]{2}|[2][0-4][0-9]|[2][0-5]{2})$", host):

            print("Scan Types: ")
            print("\n(A) Default")
            print("(B) Timed")
            print("(C) Counted (Requires administrative cmd prompt)")
            print("(D) Continuous")

            type = input("\nSelect: ")
            
            if type == "A":
                initScan(host,type)
            elif type == "B":
                tlim = input("Specify a time limit (seconds): ")
                if re.match(r"^([0-9]+)$",tlim):
                    initScan(host,type,tlim)
                else:
                    returnError(5)
            elif type == "C":
                count = input("Specify a count: ")
                if re.match(r"^([0-9]+)$",count):
                    initScan(host,type,None,count)
                else:
                    returnError(6)
            elif type == "D":
                initScan(host,type)
            elif type not in ["A","B","C","D"]:
                returnError(4)
        else:
            returnError(2) 
        
    elif opt1 == "B":
        break
    else:
        returnError(3)