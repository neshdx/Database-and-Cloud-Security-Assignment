from flask import Flask, render_template, request, redirect, session, g
import pyodbc
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ========================================
# APP SETUP
# ========================================
app = Flask(__name__)
app.secret_key = "secure_key_123"

csrf = CSRFProtect(app)
limiter = Limiter(get_remote_address, app=app)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax'
)

# ========================================
# DATABASE CONNECTION
# ========================================
DB_CONN_STR = (
    "DRIVER={ODBC Driver 17 for SQL Server};"
    "SERVER=localhost;"   # CHANGE THIS
    "DATABASE=parcel_db;"
    "Trusted_Connection=yes;"
    "MARS_Connection=yes;"
)

def get_db():
    if 'db' not in g:
        g.db = pyodbc.connect(DB_CONN_STR, autocommit=False)
    return g.db

@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db:
        db.close()

# ========================================
# AUTH ROUTES
# ========================================
@app.route("/")
def login_page():
    return render_template("login.html")


@app.route("/register", methods=["POST"])
def register():
    username = request.form["username"]
    password = request.form["password"]
    role = request.form.get("role", "user")

    hashed = generate_password_hash(password)

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO Users (username, password_hash, role)
        VALUES (?, ?, ?)
    """, (username, hashed, role))

    conn.commit()
    return redirect("/")


@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    username = request.form["username"]
    password = request.form["password"]

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT user_id, password_hash, role
        FROM Users WHERE username=?
    """, (username,))

    user = cursor.fetchone()

    if user and check_password_hash(user[1], password):
        session["user_id"] = user[0]
        session["role"] = user[2]
        return redirect("/dashboard")

    return "Invalid login"


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# ========================================
# DASHBOARD
# ========================================
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect("/")

    return render_template("dashboard.html", role=session["role"])

# ========================================
# ADD PARCEL (COURIER)
# ========================================
@app.route("/add_parcel", methods=["POST"])
def add_parcel():
    if session.get("role") != "courier":
        return "Access denied"

    parcel_id = request.form["parcel_id"]
    student_name = request.form["student_name"]
    contact = request.form["contact"]

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO Parcels (parcel_id, student_name, student_contact, courier_id)
        VALUES (?, ?, ?, ?)
    """, (parcel_id, student_name, contact, session["user_id"]))

    conn.commit()
    return redirect("/parcels")

# ========================================
# VIEW PARCELS
# ========================================
@app.route("/parcels")
def parcels():
    if "user_id" not in session:
        return redirect("/")

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM Parcels")
    data = cursor.fetchall()

    return render_template("parcels.html", parcels=data)

# ========================================
# DELETE PARCEL (ADMIN)
# ========================================
@app.route("/delete_parcel/<parcel_id>")
def delete_parcel(parcel_id):
    if session.get("role") != "admin":
        return "Access denied"

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("DELETE FROM Parcels WHERE parcel_id=?", (parcel_id,))
    conn.commit()

    return redirect("/parcels")

# ========================================
# MARK COLLECTED (USER)
# ========================================
@app.route("/mark_collected/<parcel_id>")
def mark_collected(parcel_id):
    if session.get("role") != "user":
        return "Access denied"

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE Parcels
        SET collected=1
        WHERE parcel_id=?
    """, (parcel_id,))

    conn.commit()
    return redirect("/parcels")

# ========================================
# RUN APP
# ========================================
if __name__ == "__main__":
    app.run(debug=True) 