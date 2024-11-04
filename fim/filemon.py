import datetime
import hashlib
import time

log = "fim/fimlog.txt"

def recurseHash(target_file):
    timestamp = datetime.datetime.now()
    sha256 = hashlib.sha256()
    sha256sum = sha256.hexdigest()
    try:
        with open (target_file, "rb") as tf:
            for byte_block in iter(lambda: tf.read(4096),b""):
                sha256.update(byte_block)
    except FileNotFoundError:
        print("Specified file path not found")
    with open(log, "a") as l:
        l.write("\nDATETIME: " + str(timestamp) + " FILEPATH: " + str(target_file) + " SHA256: " + str(sha256sum))

def startup(file_path,tlim):
    timestamp = datetime.datetime.now()
    with open(log, "a") as l:
        l.write("INITIATED AT: " + str(timestamp))
    while True:
        recurseHash(file_path)
        time.sleep(int(tlim))

while True:
    print("Options:")
    print("\n(A) Quickstart")
    opt1 = input("\nSelect: ")

    if opt1 == "A":
        file_path = r"C:/Users/benjaminh/fimtest.txt"
        tlim = 3
        startup(file_path,tlim)
    else:
        print("invalid")
        break