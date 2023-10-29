import re
import hashlib
import bcrypt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def Register():
    email = input("Enter your email: ")
    password = input("Enter your password: ")


    if not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email):
        print(" Your email is invalid ")
        return

    if not re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$", password):
        print("Your password is not correct ")
        return

    
    with open("Enregistrement.txt", "a") as f:
        f.write(f"{email}:{bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')}\n")
    print("You are registered succesfully!!")


def Login():
    email = input("Enter your email : ")
    password = input("Enter your password : ")

    with open("Enregistrement.txt", "r") as f:
        for line in f:
            stored_email, stored_password = line.strip().split(":")
            if email == stored_email and bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
                print("Authentification réussie!")
                menu_principal()
                return
    print("Invalid Credential!")


def menu_principal():
    print("Menu:")
    print("A- Give a pwd to be hashed")
    print("B- Encryption (RSA)")
    print("C- Certificate (RSA)")
    choix = input("Pick an option (A/B/C) : ")

    if choix == 'A':
        menu_hachage()
    elif choix == 'B':
        menu_rsa()
    elif choix == 'C':
        menu_certificat()
    else:
        print("Invalid option")


def menu_hachage():
    print("Hash menu:")
    print("a- Hash the pwd by sha256")
    print("b- Hash the pwd by generating a salt (bcrypt)")
    print("c- Dictionary attack the inserted pwd")
    print("d- Return to main menu")
    choix = input("Pick an option (a/b/c/d) : ")

    if choix == 'a':
        mot_a_hacher = input("Enter the pword to hash  by sha256: ")
        hache_sha256(mot_a_hacher)
    elif choix == 'b':
        mot_a_hacher = input("Enter the pword to hash by generating a salt (bcrypt) : ")
        hache_bcrypt(mot_a_hacher)
    elif choix == 'c':
        dictionary_attack()
    elif choix == 'd':
        menu_principal()
    else:
        print("Invalid option")


def hache_sha256(mot):
    hache = hashlib.sha256(mot.encode()).hexdigest()
    print(f"SHA-256 hash result: {hache}")


def hache_bcrypt(mot):
    sel = bcrypt.gensalt()
    hache = bcrypt.hashpw(mot.encode(), sel).decode('utf-8')
    print(f"SHA-256 hash result: {hache}")

def dictionary_attack():
    hashed_passwords = [] 
    dictionary = ["password1", "password2", "password3"] 

    
    with open("Enregistrement.txt", "r") as f:
        for line in f:
            _, stored_password = line.strip().split(":")
            hashed_passwords.append(stored_password)

   
    for password in dictionary:
        for hashed_password in hashed_passwords:
            if bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
                print(f"Password found: {password}")
                return

    print("Dictionary attack finished, no password found.")

def menu_rsa():
    print("RSA menu:")
    print("a- Generate key pairs in a file")
    print("b- Encrypt a message of your choice using RSA")
    print("c- Decipher the message (b)")
    print("d- Sign a message of your choice by RSA")
    print("e- Return to main menu")
    choix = input("Pick an option (a/b/c/d/e) : ")



def menu_certificat():
    print("RSA menu:")
    print("a- Generate key pairs in a file")
    print("b- Generate a self-signed certificate by RSA")
    print("c- Encrypt a message of your choice using this certificate")
    print("d- Return to main menu")
    choix = input("Pick an option (a/b/c/d) : ")

  

# -------------------Programme principal------------------
while True:
    print("1- Register")
    print("2- Login")
    choix = input("Pick one option (1/2) : ")

    if choix == '1':
        Register()
    elif choix == '2':
        Login()
        break
    else:
        print("Invalid option")
