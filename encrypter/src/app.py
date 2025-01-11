import os
from dotenv import load_dotenv
from cs50 import SQL  # type: ignore
from flask import Flask, flash, redirect, render_template, request, session, send_from_directory  # type: ignore
from flask_session import Session  # type: ignore
from werkzeug.security import check_password_hash, generate_password_hash  # type: ignore
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives import serialization
from helpers import apology, login_required, generate_rsa_keypair, encrypt_private_key, allowed_file, encrypt_file, decrypt_private_key, decrypt_file, cleanup_after_request  # type: ignore

app = Flask(__name__)

UPLOAD_FOLDER = "./uploads"
DOWNLOAD_FOLDER = "./downloads"
ENCRYPT_FOLDER = "./encrypted"
DECRYPT_FOLDER = "./decrypted"


app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["DOWNLOAD_FOLDER"] = DOWNLOAD_FOLDER
app.config["DECRYPT_FOLDER"] = DECRYPT_FOLDER
app.config["ENCRYPTED_FOLDER"] = ENCRYPT_FOLDER
app.config["SESSION_PERMANENT"] = True
app.config["SESSION_TYPE"] = "filesystem"

# Register the after_request handler once
app.after_request(cleanup_after_request)

#create sessions
Session(app)

db = SQL("sqlite:///encrypter.db")

# load .env variables automatically
load_dotenv()

secret_key = os.getenv("SECRET_KEY")

if __name__ == "__main__":
    app.run(debug=False)
    
@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    encryptions = db.execute(
        "SELECT file_name FROM encryptions WHERE ? = user_id", session["user_id"]
    )
    if encryptions:
        encryptions_bool = True
    else:
        encryptions_bool = False
    return render_template(
        "index.html", encryptions_bool=encryptions_bool, encryptions=encryptions
    )


@app.route("/encrypt", methods=["GET", "POST"])
@login_required
def encrypt():
    if request.method == "POST":
        # check if the post request has the file part
        if "file" not in request.files:
            return apology("No file part")
        file = request.files["file"]
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == "":
            return apology("No selected file")
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

            # Retrieve the public key from session and load it
            public_key_pem_temp = db.execute(
                "SELECT public_key FROM users WHERE ? = id", session["user_id"]
            )
            public_key_pem = public_key_pem_temp[0]["public_key"]
            if public_key_pem:
                public_key = serialization.load_pem_public_key(public_key_pem)
            else:
                return apology("Somthing went wrong when accessing Public Key")
            already = db.execute(
                "SELECT file_name FROM encryptions WHERE ? = user_id AND ? = file_name",
                session["user_id"],
                filename,
            )
            if already:
                return apology(f"you already encryted a file named{filename}")
            input_file = f"uploads/{filename}"
            output_file = f"encrypted/{filename}"
            try:
                encrypt_file(
                    input_file, public_key, output_file, filename, session["user_id"]
                )
                # delete input file 
                os.remove(input_file)
                print(f"Successfully deleted {input_file}")
            except:
                return apology("Something went wrong while encrypting the file")
            return redirect(f"/encrypt/download/{filename}")
    else:
        return render_template("encrypt.html")


@app.route("/encrypt/download/<path:filename>", methods=["GET"])
@login_required
def download_file_encrypt(filename):
    try:
        encrypted_folder = app.config.get("ENCRYPTED_FOLDER", "./encrypted")
        response = send_from_directory(
            directory=encrypted_folder,
            path=filename,
            as_attachment=True
        )
        response.headers['X-File-To-Delete'] = os.path.join(encrypted_folder, filename)
        return response
    except Exception as e:
        print(f"Error occurred: {e}")
        return apology("Something went wrong while downloading the file")




@app.route("/decrypt", methods=["GET", "POST"])
@login_required
def decrypt():
    if request.method == "POST":
        # check if the post request has the file part
        if "file" not in request.files:
            return apology("No file part")
        file = request.files["file"]
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == "":
            return apology("No selected file")
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config["DOWNLOAD_FOLDER"], filename))
            privat_key_information = db.execute(
                "SELECT encrypted_key, salt, iv FROM users WHERE ? = id",
                session["user_id"],
            )
            encrypted_private_key = privat_key_information[0]["encrypted_key"]
            salt = privat_key_information[0]["salt"]
            iv = privat_key_information[0]["iv"]
            private_key = decrypt_private_key(
                encrypted_private_key, secret_key, salt, iv
            )
            ciphertext_file = f"downloads/{filename}"
            output_file = f"decrypted/{filename}"
            try:
                decrypt_file(
                    ciphertext_file,
                    private_key,
                    output_file,
                    filename,
                    session["user_id"],
                )
                return redirect(f"/decrypt/download/{filename}")
            except:
                return apology("Something went wrong while decrypting the file")
    else:
        return render_template("decrypt.html")


@app.route("/decrypt/download/<path:filename>", methods=["GET"])
@login_required
def download_file_decrypt(filename):
    try:
        decrypted_folder = app.config.get("DECRYPTED_FOLDER", "./decrypted")
        response = send_from_directory(
            directory=decrypted_folder,
            path=filename,
            as_attachment=True
        )
        response.headers['X-File-To-Delete'] = os.path.join(decrypted_folder, filename)
        return response
    except Exception as e:
        print(f"Error occurred: {e}")
        return apology("Something went wrong while downloading the file")

@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()
    if request.method == "POST":
        if not request.form.get("username"):
            return apology("must provide username", 403)

        elif not request.form.get("password"):
            return apology("must provide password", 403)
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )
        
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash_password"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)
        session["user_id"] = rows[0]["id"]
        return redirect("/")
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    session.clear()
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if not username:
            return apology("must provide username", 403)
        elif not password:
            return apology("must provide password", 403)
        # Check if username already exists
        existing_user = db.execute("SELECT * FROM users WHERE username = ?", username)
        if existing_user:
            return apology("username already taken", 403)

        # generate private and public key
        private_key, public_key = generate_rsa_keypair()

        # Store the public key in db as PEM
        public_key_temp = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        result = encrypt_private_key(private_key, secret_key)
        encrypted_key = result["encrypted_key"]
        salt = result["salt"]
        iv = result["iv"]
        # Insert new user
        hash_password = generate_password_hash(password)
        db.execute(
            "INSERT INTO users (username, hash_password, encrypted_key, public_key, salt, iv) VALUES (?,?,?,?,?,?)",
            username,
            hash_password,
            encrypted_key,
            public_key_temp,
            salt,
            iv,
        )

        # Log the user in
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)
        session["user_id"] = rows[0]["id"]
        return redirect("/")
    else:
        return render_template("register.html")