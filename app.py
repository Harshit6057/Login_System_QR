from flask import Flask, render_template, request, redirect, url_for, session , jsonify
import sqlite3, hashlib, uuid, qrcode, os, time


app = Flask(__name__)
app.secret_key = "super_secret_key"

DB = "database.db"
QR_TOKENS = {}

#DATABASE
def get_db():
  return sqlite3.connect(DB)

def init_db():
  with get_db() as con:
    con.execute("""
                CREATE TABLE IF NOT EXISTS users (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE,
                  password TEXT
                  )
                  """)
    
init_db()

#HELPERS
def hash_password(password):
  return hashlib.sha256(password.encode()).hexdigest()

#REGISTER
@app.route("/register", methods = ["GET","POST"])
def resgister():
  if request.method == "POST":
    username = request.form["username"]
    password = hash_password(request.form["password"])
    
    try:
      with get_db() as con:
        con.execute("INSERT INTO users (username, password) VALUES (?,?)",
                    (username , password))
    
      return redirect("/login")
    except:
        return "Username already exists"

  return render_template("register.html")
    

# ---------- LOGIN (USERNAME/PASSWORD) ----------
@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = hash_password(request.form["password"])

        cur = get_db().execute(
            "SELECT * FROM users WHERE username=? AND password=?",
            (username,password)
        )

        if cur.fetchone():
            session["user"] = username
            return redirect("/dashboard")

        return "Invalid credentials"

    return render_template("login.html")



#QR LOGIN PAGE

@app.route("/qr_login")
def qr_login():
    token = str(uuid.uuid4())
    QR_TOKENS[token] = (None, time.time() + 60)

    public_base_url = "https://oozy-adrianne-nonlyrical.ngrok-free.dev"
    qr_url = f"{public_base_url}/qr-auth/{token}"

    img = qrcode.make(qr_url)
    img.save("static/qr.png")

    return render_template("qr_login.html")



# ---------- QR SCAN (SIMULATED MOBILE APP) ----------
@app.route("/scan-qr", methods=["POST"])
def scan_qr():
    token = request.json["token"]
    username = request.json["username"]

    if token in QR_TOKENS:
        QR_TOKENS[token] = (username, QR_TOKENS[token][1])
        return jsonify({"status":"approved"})

    return jsonify({"status":"invalid"})
  
  
# ---------- CHECK QR STATUS ----------
@app.route("/check-qr/<token>")
def check_qr(token):
    if token in QR_TOKENS:
        username, expiry = QR_TOKENS[token]
        if time.time() > expiry:
            return jsonify({"status":"expired"})
        if username:
            session["user"] = username
            del QR_TOKENS[token]
            return jsonify({"status":"success"})
    return jsonify({"status":"waiting"})
  
  
  

@app.route("/qr-auth/<token>")
def qr_auth(token):
    if token not in QR_TOKENS:
        return "Invalid or expired QR", 400

    username, expiry = QR_TOKENS[token]

    if time.time() > expiry:
        return "QR expired", 400

    # Simulate login approval
    # In real apps, user confirms on mobile
    session["user"] = "testuser"  # or actual user
    del QR_TOKENS[token]

    return redirect("/dashboard")



  
# ---------- DASHBOARD ----------
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/login")
    return render_template("dashboard.html", user=session["user"])

# ---------- LOGOUT ----------
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")
  
@app.route("/")
def home():
    return redirect("/login")


if __name__ == "__main__":
    app.run(debug=True)