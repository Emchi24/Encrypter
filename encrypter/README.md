# Encrypter

A secure Flask web application that enables users to encrypt and decrypt text files using RSA and AES encryption. The application combines asymmetric (RSA) and symmetric (AES) encryption to provide secure file handling while maintaining efficient performance.

## Features

- User authentication system
- RSA key pair generation for each user
- Secure file encryption using hybrid encryption (RSA + AES)
- File upload and download functionality
- Automatic file cleanup after operations
- session managment

## Security Architecture

### Encryption Process
1. When a file is uploaded for encryption:
   - A random AES-256 key is generated
   - The file is encrypted using AES in CBC mode with PKCS7 padding
   - The AES key is encrypted using the user's RSA public key

### Decryption Process
1. When decrypting a file:
   - The encrypted AES key is retrieved and decrypted using the user's RSA private key
   - The file is decrypted using the recovered AES key
   - PKCS7 padding is removed to restore the original file

### Key Management
- Each user gets a unique RSA key pair upon registration
- The private key is encrypted using a master key from the `.env` file
- Only encrypted versions of private keys are stored in the database
- Public keys are stored in PEM format

## Installation (for Debian based Linux versions)

1. Clone the repository:
```bash
git clone https://github.com/Emchi24/Encrypter
cd Encrypter
```
2. Install python venv
```bash
sudo apt update
sudo apt install python-venv
```

3. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  
```
4. Move src folder in virtual environment: 
```bash
mv encrypter/src venv/            
cd venv/src    
```
5. Install required packages:
```bash
pip install -r requirements.txt
```

6. Create necessary directories in the src folder:
```bash
mkdir /uploads /downloads /encrypted /decrypted
```

7. Create a `.env` file in the src directory:
```bash
touch .env
```

8. Create and safe your own random key to encrypt private key
```bash
echo "SECRET_KEY=$(openssl rand -hex 32)" >> .env
```

9. Install sqlite3
```bash
sudo apt update
sudo apt install sqlite3
```

10. Create your one sqlite3 database
```bash
touch encrypter.db
sqlite3 encrypter.db
```
Create Tables in database
```bash
CREATE TABLE sqlite_sequence(name,seq);
CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, username TEXT NOT NULL, hash_password TEXT NOT NULL, encrypted_key TEXT NOT NULL, public_key TEXT NOT NULL, salt TEXT NOT NULL, iv TEXT NOT NULL);
CREATE TABLE encryptions (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, user_id INTEGER NOT NULL, file_name TEXT NOT NULL, shared_secret BLOB NOT NULL, iv BLOB NOT NULL, timestamp DATETIME NOT NULL);
CREATE UNIQUE INDEX username ON users (username);
```
11. quit database
```bash
.quit
```
## Directory Structure (src folder)

```
src/
├── static/
│   └── favicon.ico
├── templates/
│   ├── apology.html
│   ├── decrypt.html
│   ├── encrypt.html
│   ├── index.html
│   ├── layout.html
│   ├── login.html
│   └── register.html
├── uploads/         # Temporary storage for uploaded files
├── downloads/       # Temporary storage for files to be decrypted
├── encrypted/       # Temporary storage for encrypted files
├── decrypted/       # Temporary storage for decrypted files
├── app.py           # Main application file
├── helpers.py       # Helper functions
├── encrypter.db     # sqlite3 database 
├── requirements.txt # information for packages installing
└── .env             # Environment variables
```

## Usage

1. Start the application:
```bash
flask run app.py
```

2. Register a new account:
   - Visit `/register`
   - When submitting username and password the application will automatically generate your encryption keys

3. Encrypt a file:
   - Navigate to the encryption page
   - Upload a text file
   - clik on encrypt

4. Decrypt a file:
   - Navigate to the decryption page
   - Upload an encrypted file
   - clik on decrypt

## Security requirements

- All temporary files are automatically deleted after operations
- All user passwords are hashed using Werkzeug's security features
- The master encryption key must be kept secure in the `.env` file

## Database Schema

The application uses SQLite with two main tables:

### Users Table
- id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
- username TEXT NOT NULL,
- hash_password TEXT NOT NULL,
- encrypted_key TEXT NOT NULL,
- public_key TEXT NOT NULL,
- salt TEXT NOT NULL,
- iv TEXT NOT NULL

### Encryptions Table
- id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
- user_id INTEGER NOT NULL, file_name TEXT NOT NULL,
- shared_secret BLOB NOT NULL,
- iv BLOB NOT NULL,
- timestamp DATETIME NOT NULL

## Dependencies

- Flask
- CS50
- cryptography
- Werkzeug
- python-dotenv
- Flask-Session