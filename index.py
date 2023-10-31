import re
import hashlib
import bcrypt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import datetime
from cryptography import x509

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
    dictionary = ["Koukou123**", "Azerty123**", "Qwerty123**"] 

    
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
    print("e- Return to the main menu")
    choix = input("Pick an option (a/b/c/d/e) : ")

    if choix == 'a':
        generate_rsa_key_pair()
    elif choix == 'b':
        message = input("Enter the message to encrypt using RSA: ")
        encrypt_rsa_message(message)
    elif choix == 'c':
        # Implement decryption logic here
        pass
    elif choix == 'd':
        message = input("Enter the message to sign using RSA: ")
        sign_rsa_message(message)
    elif choix == 'e':
        menu_principal()
    else:
        print("Invalid option")

def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    with open("private_key.pem", "wb") as f:
        private_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        )
        f.write(private_pem)

    public_key = private_key.public_key()
    with open("public_key.pem", "wb") as f:
        public_pem = public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        f.write(public_pem)

    print("RSA key pair generated and saved to private_key.pem and public_key.pem")

def encrypt_rsa_message(message):
    with open("public_key.pem", "rb") as public_key_file:
        public_key = serialization.load_pem_public_key(
            public_key_file.read(),
            backend=default_backend()
        )

    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open("encrypted_message.bin", "wb") as encrypted_file:
        encrypted_file.write(ciphertext)

    print("Message encrypted with RSA and saved to encrypted_message.bin")

def sign_rsa_message(message):
    with open("private_key.pem", "rb") as private_key_file:
        private_key = serialization.load_pem_private_key(
            private_key_file.read(),
            password=None,
            backend=default_backend()
        )

    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    with open("message_signature.bin", "wb") as signature_file:
        signature_file.write(signature)

    print("Message signed with RSA and saved to message_signature.bin")



def menu_certificat():
    print("RSA menu:")
    print("a- Generate key pairs in a file")
    print("b- Generate a self-signed certificate by RSA")
    print("c- Encrypt a message of your choice using this certificate")
    print("d- Return to main menu")
    choix = input("Pick an option (a/b/c/d) : ")
    
    if choix == 'a':
        generate_rsa_key_pair()
    elif choix == 'b':
        generate_self_signed_certificate()
    elif choix == 'c':
        message = input("Enter the message to encrypt using the certificate: ")
        encrypt_message_with_certificate(message)
    elif choix == 'd':
        menu_principal()
    else:
        print("Invalid option")

def generate_self_signed_certificate():
    with open("private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    subject = x509.Name([
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, "CA"),
        x509.NameAttribute(x509.NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "My Organization"),
        x509.NameAttribute(x509.NameOID.COMMON_NAME, "example.com")
    ])

    certificate = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        subject
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).sign(private_key, hashes.SHA256(), default_backend())

    with open("self_signed_certificate.pem", "wb") as cert_file:
        cert_file.write(certificate.public_bytes(encoding=serialization.Encoding.PEM))

    print("Self-signed certificate generated and saved to self_signed_certificate.pem")

def encrypt_message_with_certificate(message):
    with open("self_signed_certificate.pem", "rb") as cert_file:
        certificate = x509.load_pem_x509_certificate(cert_file.read(), default_backend())

    public_key = certificate.public_key()

    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open("encrypted_message_with_certificate.bin", "wb") as encrypted_file:
        encrypted_file.write(ciphertext)

    print("Message encrypted with the certificate and saved to encrypted_message_with_certificate.bin")

  

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
