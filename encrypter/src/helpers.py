from flask import redirect, render_template, session
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import padding as sym_padding
import os
import base64
from functools import wraps
from cs50 import SQL

db = SQL("sqlite:///encrypter.db")
ALLOWED_EXTENSIONS = {"txt"}


def generate_rsa_keypair():
    """Generiert ein RSA-Schlüsselpaar"""
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )

    public_key = private_key.public_key()
    print("Schlüsselpaar erfolgreich generiert und gespeichert.")
    return private_key, public_key


# Funktion zur Verschlüsselung des privaten Schlüssels
def encrypt_private_key(private_key, password):
    # Salt für Key-Derivation
    salt = os.urandom(584707)

    # Key-Derivation mit PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    encryption_key = kdf.derive(password.encode())

    # Initialisierungsvektor (IV) für AES
    iv = os.urandom(16)

    # Private Key in PEM-Format serialisieren
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # AES-Verschlüsselung
    cipher = Cipher(algorithms.AES(encryption_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_private_key = encryptor.update(private_key_pem) + encryptor.finalize()

    # Rückgabe von verschlüsseltem Schlüssel, Salt und IV
    return {
        "encrypted_key": base64.b64encode(encrypted_private_key).decode(),
        "salt": base64.b64encode(salt).decode(),
        "iv": base64.b64encode(iv).decode(),
    }


# Funktion zur Entschlüsselung des privaten Schlüssels
def decrypt_private_key(encrypted_key, password, salt, iv):
    # Base64-Dekodierung
    encrypted_key = base64.b64decode(encrypted_key)
    salt = base64.b64decode(salt)
    iv = base64.b64decode(iv)

    # Key-Derivation
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    decryption_key = kdf.derive(password.encode())

    # AES-Entschlüsselung
    cipher = Cipher(algorithms.AES(decryption_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    private_key_pem = decryptor.update(encrypted_key) + decryptor.finalize()

    # Privaten Schlüssel aus PEM laden
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
    )
    print("Privater Schlüssel erfolgreich geladen!")

    return private_key


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def apology(message, code=400):
    def escape(s):
        for old, new in [
            ("-", "--"),
            (" ", "-"),
            ("_", "__"),
            ("?", "~q"),
            ("%", "~p"),
            ("#", "~h"),
            ("/", "~s"),
            ('"', "''"),
        ]:
            s = s.replace(old, new)
        return s

    return render_template("apology.html", top=code, bottom=escape(message)), code


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)

    return decorated_function


# Verschlüsseln einer Datei mit PKCS7-Padding
def encrypt_file(input_file: str, public_key, ciphertext_file: str, filename, user_id):
    """Verschlüsselt eine Datei mit einem AES-Schlüssel, der durch RSA geschützt ist."""
    try:
        # Datei lesen
        with open(input_file, "rb") as f:
            plaintext = f.read()

        # Erstellen eines symmetrischen Schlüssels (AES) mit einem zufälligen 256-Bit-Schlüssel
        aes_key = os.urandom(32)  # AES-256

        # Initialisierungsvektor (IV) für den CBC-Modus
        iv = os.urandom(16)

        # PKCS7-Padding hinzufügen
        padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext) + padder.finalize()

        # Verschlüsseln der Datei mit AES im CBC-Modus
        cipher = Cipher(
            algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        # Verschlüsseln des AES-Schlüssels mit RSA
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # Ciphertext und verschlüsselten AES-Schlüssel speichern
        with open(ciphertext_file, "wb") as f:
            f.write(ciphertext)  # IV wird vor dem Ciphertext gespeichert

        db.execute(
            "INSERT INTO encryptions (file_name, shared_secret, iv, user_id) VALUES (?,?,?,?)",
            filename,
            encrypted_aes_key,
            iv,
            user_id,
        )

        print(f"Datei '{input_file}' erfolgreich verschlüsselt.")

    except Exception as e:
        print(f"Fehler beim Verschlüsseln: {e}")


# Entschlüsseln einer Datei mit PKCS7-Padding


def decrypt_file(
    ciphertext_file: str, private_key, output_file: str, filename, user_id
):
    """Entschlüsselt eine Datei mit einem RSA-privaten Schlüssel und AES."""
    try:
        # Daten laden
        with open(ciphertext_file, "rb") as f:
            ciphertext = f.read()

        encrypted_file_information = encrypted_file_information = db.execute(
            "SELECT shared_secret, iv FROM encryptions WHERE ? = user_id AND ? = file_name",
            user_id,
            filename,
        )

        iv = encrypted_file_information[0]["iv"]
        encrypted_aes_key = encrypted_file_information[0]["shared_secret"]

        # Entschlüsseln des AES-Schlüssels mit RSA
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # Entschlüsseln des Ciphertexts mit AES im CBC-Modus
        cipher = Cipher(
            algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # PKCS7-Padding entfernen
        unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        # Entschlüsselte Daten speichern
        with open(output_file, "wb") as f:
            f.write(plaintext)

        print(f"Datei '{ciphertext_file}' erfolgreich entschlüsselt.")

    except Exception as e:
        print(f"Fehler beim Entschlüsseln: {e}")
