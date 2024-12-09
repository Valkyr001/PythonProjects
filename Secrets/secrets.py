#notes
#add security to clearvault function to prevent arbitrary deletion of files

#imports
import argparse #for argument handling
import os #for some of the file/folder handling operations
import shutil #required for deleting directories and their contents

#args
def parse():
    parser = argparse.ArgumentParser(description="Python script for secrets management. Expanded version of PWM.")
    #vault directory handling
    parser.add_argument("-C", "--createvault", help="Create a new vault directory.", action="store_true")
    parser.add_argument("-L", "--listvaults", help="List all existing vaults.", action="store_true")
    parser.add_argument("-R", "--readvault", help="List the secrets stored in a specified vault file.", action="store_true")
    parser.add_argument("-D", "--deletevault", help="Delete a vault directory.", action="store_true")
    #secret handling
    parser.add_argument("-c", "--createsecret", help="Create a new secret.", action="store_true")
    #secret type (required if using -c)
    parser.add_argument("-P", "--credentialpair", help="Save both a username and a password as a stored secret.", action="store_true")
    parser.add_argument("-p", "--password", help="Save only a password as a stored secret.", action="store_true")
    parser.add_argument("-n", "--note", help="Save an encrypted note.", action="store_true")
    parser.add_argument("-f", "--file", help="Encrypt a specified file.", action="store_true")
    #secret handling (continued)
    parser.add_argument("-r", "--readsecret", help="Decrypt and read a stored secret.", action="store_true")
    parser.add_argument("-d", "--deletesecret", help="Delete a stored secret.", action="store_true")

    return parser.parse_args()

#secrets and vault systems
    #create vaults
    #delete vaults
    #list vaults
    #list vault contents
    #create a secret
        #secret types
            #credential pair
            #encrypted note
            #encrypted system file (copied)
    #read a secret
    #delete a secret

def main():
    args = parse()

    def createVault():
        if os.path.exists("Vaults"):
            pass
        else:
            os.makedirs("Vaults")
            print("\n[+] No vault folder exists. Initializing.")
        name = input("\n[>] Enter a name for the vault: ")
        newvault = "Vaults/" + name
        try:
            os.makedirs(newvault)
            print("[+] New vault created successfully.")
            path = os.path.abspath(newvault)
            print(f"[+] File Location: {path}")
        except FileExistsError:
            print("[!] A folder with this name already exists.")
        except PermissionError:
            print("[!] You do not have permission to create a folder at this location.")

    def deleteVault():
        name = input("\n[>] Specify the name of the vault to delete: ")
        path = "Vaults/" + name
        confirm = input("[>] Are you sure? All vault contents will be lost. (y/n): ")
        if confirm.lower() == "y":
            try:
                shutil.rmtree(path)
                print("[+] Vault deleted successfully.")
            except PermissionError:
                print("[!] You do not have permission to delete this folder or its contents.")
            except FileNotFoundError:
                print("[!] The specified file name could not be identified.")
        else:
            print("[+] Aborting vault deletion.")

    def listVaults():
        if os.path.exists("Vaults"):
            vaultsfolder = os.path.abspath("Vaults")
        else:
            print("\n[!] No vaults folder exists, it is automatically created when using -C")
            return
        if len(os.listdir(vaultsfolder)) > 0:
            print("\n[+] Vaults:" )
            for v in os.listdir(vaultsfolder):
                vault = "[-] " + v
                print(vault)
        else:
            print("\n[!] No vault files exist.")
    
    def readVault():
        name = input("\n[>] Specify the name of the vault: ")
        vault = "Vaults/" + name
        if os.path.exists(vault):
            secrets = os.listdir(vault)
            print("[+] Stored Secrets: ")
            for secret in secrets:
                s = "[-] " + secret
                print(s)
        else:
            print("[!] Vault does not exist.")    
                
    if args.createvault:
        createVault()
    elif args.deletevault:
        deleteVault()
    elif args.listvaults:
        listVaults()
    elif args.readvault:
        readVault()
#data systems
    #script version

#call functions

main()

