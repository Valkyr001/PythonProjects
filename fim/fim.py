import datetime
import hashlib
import time

def hashFile(file_path):
    with open("fim/fimlog.txt","a") as l:

        sha256 = hashlib.sha256()

        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096),b""):
                sha256.update(byte_block)
        x = datetime.datetime.now()
        hexd = sha256.hexdigest()
        l.write(str(x) + " File Hash: " + str(hexd))
    

def startup(file_path,tlim):
    hashFile(file_path)
    time.sleep(int(tlim))
  

while True:
    print("Options: ")
    print("\n(A) Create a task")
    print("(B) Print the log file")
    print("(C) End the program")
    opt1 = input("\nSelect: ")

    if opt1 == "A":
        file_path = input("Specify the full file path: ")
        print("Specify the hash interval in: ")
        print("\n (A) Seconds")
        opt2 = input("\nSelect: ")
        if opt2 == "A":
            tlim = input("After how many seconds should the check run? ")
            print("New task created: ")
            print("\nFile Path: " + file_path)
            print("Interval: Every " + tlim + " second(s)")
            startup(file_path,tlim)

    elif opt1 == "B":
        try:
            with open("fimlog.txt","r") as r:
                print(r.read())
        except FileNotFoundError:
            print("Error no log file exists.")
    elif opt1 == "C":
        break
        
