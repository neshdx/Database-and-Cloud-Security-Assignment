from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response, g  

import pyodbc  
from datetime import datetime, timedelta
from io import BytesIO

# ========================================
# SECURITY
# ========================================
from werkzeug.security import generate_password_hash, check_password_hash  
from flask_wtf.csrf import CSRFProtect  
from flask_limiter import Limiter 
from flask_limiter.util import get_remote_address  

# ========================================
# PDF
# ========================================
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import (
    SimpleDocTemplate,
    Table,
    TableStyle,
    Paragraph
)

# ========================================
# APP SETUP
# ========================================
app = Flask(__name__)

app.secret_key = "secure_parcel_system_key"

app.permanent_session_lifetime = timedelta(minutes=30)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax'
)

# ========================================
# CSRF + RATE LIMITER
# ========================================
csrf = CSRFProtect(app)
from flask_wtf.csrf import generate_csrf

@app.context_processor
def csrf_token_context():
    return dict(csrf_token=generate_csrf)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# ========================================
# DATABASE CONNECTION
# ========================================
DB_CONN_STR = (
    "DRIVER={ODBC Driver 17 for SQL Server};"
    "SERVER=localhost;"
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
# PREDEFINED ADMINS
# ========================================
valid_credentials = {
    'VISHAL': 'vishal123',
    'DINESH': 'dinesh123',
    'IZAAN': 'izaan123',
    'ARINI': 'arini123'
}

# ========================================
# HOME
# ========================================
@app.route('/')
def home():
    return render_template("home.html")

# ========================================
# ADMIN LOGIN
# ========================================
@app.route('/admin_login', methods=["GET", "POST"])
@limiter.limit("5 per minute")
def admin_login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        if username in valid_credentials and valid_credentials[username] == password:

            session["username"] = username
            session["role"] = "Admin"

            return redirect('/admin_dashboard')

        return render_template(
            "admin_login.html",
            error="Invalid Admin credentials!"
        )

    return render_template("admin_login.html")

# ========================================
# ADMIN DASHBOARD
# ========================================
@app.route('/admin_dashboard')
def admin_dashboard():

    if "role" not in session or session["role"] != "Admin":

        flash("Access denied!", "danger")
        return redirect(url_for("admin_login"))

    return render_template(
        "admin_dashboard.html",
        username=session["username"]
    )

# ========================================
# VIEW ADMIN DATABASE
# ========================================
@app.route('/view_admin_database')
def view_admin_database():

    # Admin access only
    if "role" not in session or session["role"] != "Admin":

        flash("Access denied! Admins only.", "danger")
        return redirect(url_for('admin_login'))

    # Database connection
    conn = get_db()
    cursor = conn.cursor()

    # Fetch parcel records from SQL database
    cursor.execute("""
        SELECT
            parcel_id,
            student_id,
            username,
            student_contact
        FROM Parcels
    """)

    parcels = cursor.fetchall()

    # Render page
    return render_template(
        'view_admin_database.html',
        parcels=parcels
    )

# ========================================
# USER REGISTER
# ========================================
@app.route('/user_register', methods=["GET", "POST"])
def user_register():

    if request.method == "POST":

        full_name = request.form["full_name"]
        dob = request.form["dob"]
        phone_number = request.form["phone_number"]
        email = request.form["email"]
        gender = request.form["gender"]
        ic_number = request.form["ic_number"]
        address = request.form["address"]
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT *
            FROM Users
            WHERE username=? OR email=? OR ic_number=?
        """, (username, email, ic_number))

        existing_user = cursor.fetchone()

        if existing_user:
            return render_template(
                "user_register.html",
                error="User already exists!"
            )

        hashed_password = generate_password_hash(password)

        cursor.execute("""
            INSERT INTO Users
            (
                full_name,
                dob,
                phone_number,
                email,
                gender,
                ic_number,
                address,
                username,
                password_hash
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            full_name,
            dob,
            phone_number,
            email,
            gender,
            ic_number,
            address,
            username,
            hashed_password
        ))

        conn.commit()

        flash("Registration successful!", "success")
        return redirect(url_for("user_login"))

    return render_template("user_register.html")

# ========================================
# USER LOGIN
# ========================================
@app.route('/user_login', methods=["GET", "POST"])
@limiter.limit("5 per minute")
def user_login():

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT id, username, password_hash, ic_number
            FROM Users
            WHERE username=?
        """, (username,))

        user = cursor.fetchone()

        if user and check_password_hash(user[2], password):

            session["username"] = user[1]
            session["role"] = "User"
            session["student_id"] = user[3]

            return redirect('/student_dashboard')

        return render_template(
            "user_login.html",
            error="Invalid credentials!"
        )

    return render_template("user_login.html")

# ========================================
# STAFF REGISTER
# ========================================
@app.route('/staff_register', methods=["GET", "POST"])
def staff_register():

    if request.method == "POST":

        staff_email = request.form["staff_email"]
        staff_id = request.form["staff_id"]
        staff_password = request.form["staff_password"]
        staff_name = request.form["staff_name"]
        staff_contact = request.form["staff_contact"]

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT *
            FROM Staff
            WHERE staff_id=? OR staff_email=? OR staff_contact=?
        """, (
            staff_id,
            staff_email,
            staff_contact
        ))

        existing_staff = cursor.fetchone()

        if existing_staff:

            return render_template(
                "staff_register.html",
                error="Staff already exists!"
            )

        hashed_password = generate_password_hash(staff_password)

        cursor.execute("""
            INSERT INTO Staff
            (
                staff_email,
                staff_id,
                staff_password,
                staff_name,
                staff_contact
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            staff_email,
            staff_id,
            hashed_password,
            staff_name,
            staff_contact
        ))

        conn.commit()

        flash("Staff registered successfully!", "success")
        return redirect(url_for("staff_login"))

    return render_template("staff_register.html")

# ========================================
# STAFF LOGIN
# ========================================
@app.route('/staff_login', methods=["GET", "POST"])
@limiter.limit("5 per minute")
def staff_login():

    if request.method == "POST":

        staff_id = request.form["staff_id"]
        staff_password = request.form["staff_password"]

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT id, staff_password, staff_name
            FROM Staff
            WHERE staff_id=?
        """, (staff_id,))

        staff = cursor.fetchone()

        if staff and check_password_hash(staff[1], staff_password):

            session["username"] = staff[2]
            session["role"] = "Staff"

            return redirect('/staff_dashboard')

        return render_template(
            "staff_login.html",
            error="Invalid credentials!"
        )

    return render_template("staff_login.html")

# ========================================
# STAFF DASHBOARD
# ========================================
@app.route('/staff_dashboard')
def staff_dashboard():

    if "role" not in session or session["role"] != "Staff":

        flash("Access denied!", "danger")
        return redirect(url_for("staff_login"))

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM Parcels
    """)

    parcels = cursor.fetchall()

    return render_template(
        "staff_dashboard.html",
        username=session["username"],
        parcels=parcels
    )

# ========================================
# COURIER REGISTER
# ========================================
@app.route('/courier_register', methods=['GET', 'POST'])
def courier_register():

    if request.method == 'POST':

        courier_name = request.form.get('courier_name')
        courier_username = request.form.get('courier_username')
        courier_password = request.form.get('courier_password')
        courier_contact = request.form.get('courier_contact')
        courier_address = request.form.get('courier_address')

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT *
            FROM Courier
            WHERE courier_username=? OR courier_contact=?
        """, (
            courier_username,
            courier_contact
        ))

        existing = cursor.fetchone()

        if existing:

            flash("Courier already exists!", "danger")
            return redirect('/courier_register')

        hashed_password = generate_password_hash(courier_password)

        cursor.execute("""
            INSERT INTO Courier
            (
                courier_name,
                courier_username,
                courier_password,
                courier_contact,
                courier_address
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            courier_name,
            courier_username,
            hashed_password,
            courier_contact,
            courier_address
        ))

        conn.commit()

        flash("Courier registered!", "success")
        return redirect('/courier_login')

    return render_template('courier_register.html')

# ========================================
# COURIER LOGIN
# ========================================
@app.route('/courier_login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def courier_login():

    if request.method == 'POST':

        courier_username = request.form.get('courier_username')
        courier_password = request.form.get('courier_password')

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT id,
                   courier_name,
                   courier_password
            FROM Courier
            WHERE courier_username=?
        """, (courier_username,))

        courier = cursor.fetchone()

        if courier and check_password_hash(courier[2], courier_password):

            session['courier_id'] = courier[0]
            session['username'] = courier[1]
            session['role'] = "Courier"

            flash("Login successful!", "success")

            return redirect('/courier')

        flash("Invalid credentials!", "danger")

    return render_template('courier_login.html')

# ========================================
# COURIER DASHBOARD
# ========================================
@app.route('/courier')
def courier():

    if "courier_id" not in session:

        flash("Please login first.", "danger")
        return redirect('/courier_login')

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM Parcels
        WHERE courier_id=?
    """, (session['courier_id'],))

    parcels = cursor.fetchall()

    return render_template(
        'courier.html',
        parcels=parcels
    )

# ========================================
# ADD PARCEL
# ========================================
@app.route('/add_parcel', methods=['GET', 'POST'])
def add_parcel():

    if "courier_id" not in session:

        flash("Please login first.", "danger")
        return redirect('/courier_login')

    if request.method == 'POST':

        parcel_id = request.form.get('parcel_id')
        student_id = request.form.get('student_id')
        username = request.form.get('username')
        student_contact = request.form.get('student_contact')

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT *
            FROM Parcels
            WHERE parcel_id=?
        """, (parcel_id,))

        existing = cursor.fetchone()

        if existing:

            flash("Parcel ID already exists!", "danger")
            return redirect(url_for("add_parcel"))

        cursor.execute("""
            INSERT INTO Parcels
            (
                parcel_id,
                student_id,
                username,
                student_contact,
                courier_id,
                collected
            )
            VALUES (?, ?, ?, ?, ?, 0)
        """, (
            parcel_id,
            student_id,
            username,
            student_contact,
            session['courier_id']
        ))

        conn.commit()

        flash("Parcel added successfully!", "success")

        return redirect('/courier')

    return render_template('add_parcel.html')

# ========================================
# VIEW PARCELS - ADMIN
# ========================================
@app.route('/admin_parcels')
def admin_parcels():

    if "role" not in session or session["role"] != "Admin":

        flash("Admins only!", "danger")
        return redirect('/admin_login')

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM Parcels
    """)

    parcels = cursor.fetchall()

    return render_template(
        'admin_parcels.html',
        parcels=parcels,
        role="Admin"
    )

# ========================================
# STAFF PARCELS
# ========================================
@app.route('/staff_parcels')
def staff_parcels():

    if "role" not in session or session["role"] != "Staff":

        flash("Staff only!", "danger")
        return redirect('/staff_login')

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM Parcels
    """)

    parcels = cursor.fetchall()

    return render_template(
        'view_parcels.html',
        parcels=parcels,
        role="Staff"
    )

# ========================================
# MARK COLLECTED
# ========================================
@app.route('/mark_collected/<int:id>', methods=['POST'])
def mark_collected(id):

    if "username" not in session or session["role"] != "User":

        flash("Students only!", "danger")
        return redirect(url_for('user_login'))

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE Parcels
        SET collected=1
        WHERE id=? AND username=?
    """, (
        id,
        session['username']
    ))

    conn.commit()

    flash("Parcel collected!", "success")

    return redirect(url_for('collection_page'))

# ========================================
# COLLECTION PAGE
# ========================================
@app.route('/collection')
def collection_page():

    if "username" not in session or session["role"] != "User":

        flash("Students only!", "danger")
        return redirect(url_for('user_login'))

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM Parcels
        WHERE username=?
    """, (session['username'],))

    parcels = cursor.fetchall()

    return render_template(
        'collection.html',
        parcels=parcels
    )

# ========================================
# SEND NOTIFICATION
# ========================================
@app.route('/send_notification/<int:id>', methods=['POST'])
def send_notification(id):

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT username
        FROM Parcels
        WHERE id=?
    """, (id,))

    parcel = cursor.fetchone()

    if parcel:

        cursor.execute("""
            INSERT INTO Notifications
            (
                username,
                message
            )
            VALUES (?, ?)
        """, (
            parcel[0],
            "Your parcel is ready for pickup!"
        ))

        conn.commit()

        flash("Notification sent!", "success")

    return redirect(url_for('staff_dashboard'))

# ========================================
# VIEW NOTIFICATIONS
# ========================================
@app.route('/view_notifications')
def view_notifications():

    if "username" not in session:

        flash("Please login.", "danger")
        return redirect(url_for('user_login'))

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM Notifications
        WHERE username=?
    """, (session['username'],))

    notifications = cursor.fetchall()

    return render_template(
        'view_notifications.html',
        notifications=notifications
    )

# ========================================
# STUDENT DASHBOARD
# ========================================
@app.route('/student_dashboard')
def student_dashboard():

    if "username" not in session:

        flash("Please login.", "danger")
        return redirect(url_for('user_login'))

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM Parcels
        WHERE username=?
    """, (session['username'],))

    parcels = cursor.fetchall()

    cursor.execute("""
        SELECT COUNT(*)
        FROM Notifications
        WHERE username=?
    """, (session['username'],))

    count = cursor.fetchone()[0]

    has_notification = count > 0

    return render_template(
        'user_dashboard.html',
        parcels=parcels,
        has_notification=has_notification
    )

# ========================================
# FEEDBACK
# ========================================
@app.route('/submit_feedback', methods=['GET', 'POST'])
def submit_feedback():

    if "username" not in session or session["role"] != "User":

        flash("Please login as User.", "danger")
        return redirect(url_for('user_login'))

    if request.method == 'POST':

        phone_number = request.form.get('phone_number')
        message = request.form.get('message')

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO Feedback
            (
                username,
                phone_number,
                message
            )
            VALUES (?, ?, ?)
        """, (
            session['username'],
            phone_number,
            message
        ))

        conn.commit()

        flash("Feedback submitted!", "success")

        return redirect(url_for('student_dashboard'))

    return render_template('feedback_form.html')

# ========================================
# VIEW FEEDBACK
# ========================================
@app.route('/view_feedback')
def view_feedback():

    if "role" not in session or session["role"] not in ["Staff", "Courier"]:

        flash("Access denied!", "danger")
        return redirect(url_for('home'))

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM Feedback
        ORDER BY timestamp DESC
    """)

    feedbacks = cursor.fetchall()

    return render_template(
        'view_feedback.html',
        feedbacks=feedbacks
    )

# ========================================
# UPDATE PARCEL
# ========================================
@app.route('/update_parcel/<int:id>', methods=['GET', 'POST'])
def update_parcel(id):

    if 'courier_id' not in session:

        flash('Please login.', 'danger')
        return redirect(url_for('courier_login'))

    conn = get_db()
    cursor = conn.cursor()

    if request.method == 'POST':

        parcel_id = request.form['parcel_id']
        student_id = request.form['student_id']
        username = request.form['username']
        student_contact = request.form['student_contact']

        cursor.execute("""
            UPDATE Parcels
            SET parcel_id=?,
                student_id=?,
                username=?,
                student_contact=?
            WHERE id=? AND courier_id=?
        """, (
            parcel_id,
            student_id,
            username,
            student_contact,
            id,
            session['courier_id']
        ))

        conn.commit()

        flash('Parcel updated!', 'success')

        return redirect(url_for('courier'))

    cursor.execute("""
        SELECT *
        FROM Parcels
        WHERE id=? AND courier_id=?
    """, (
        id,
        session['courier_id']
    ))

    parcel = cursor.fetchone()

    return render_template(
        'edit_parcel.html',
        parcel=parcel
    )

# ========================================
# DELETE PARCEL
# ========================================
@app.route('/delete_parcel/<int:id>', methods=['POST'])
def delete_parcel(id):

    if 'courier_id' not in session:

        flash('Please login.', 'danger')
        return redirect(url_for('courier_login'))

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        DELETE FROM Parcels
        WHERE id=? AND courier_id=?
    """, (
        id,
        session['courier_id']
    ))

    conn.commit()

    flash('Parcel deleted!', 'success')

    return redirect(url_for('courier'))

# ========================================
# VIEW COLLECTION
# ========================================
@app.route('/view_collection')
def view_collection():

    if "role" not in session or session["role"] != "Admin":

        flash("Admins only!", "danger")
        return redirect('/admin_login')

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT username, collected
        FROM Parcels
    """)

    collection_data = cursor.fetchall()

    return render_template(
        'view_collection.html',
        collection_data=collection_data
    )

# ========================================
# PDF REPORT
# ========================================
@app.route('/generate_pdf_report')
def generate_pdf_report():

    if "role" not in session or session["role"] != "Admin":

        flash("Admins only!", "danger")
        return redirect('/admin_login')

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT parcel_id,
               student_id,
               username,
               student_contact
        FROM Parcels
    """)

    parcels = cursor.fetchall()

    response = make_response(generate_pdf(parcels))

    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'inline; filename=parcel_report.pdf'

    return response

# ========================================
# GENERATE PDF
# ========================================
def generate_pdf(data):

    buffer = BytesIO()

    pdf = SimpleDocTemplate(
        buffer,
        pagesize=letter
    )

    styles = getSampleStyleSheet()

    title = Paragraph(
        "Parcel Report",
        styles['Title']
    )

    table_data = [[
        "Parcel ID",
        "Student ID",
        "Username",
        "Contact"
    ]]

    for row in data:
        table_data.append(list(row))

    table = Table(table_data)

    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))

    elements = [title, table]

    pdf.build(elements)

    pdf_content = buffer.getvalue()

    buffer.close()

    return pdf_content

# ========================================
# DASHBOARD
# ========================================
@app.route('/dashboard')
def dashboard():

    if "username" in session:

        return render_template(
            "dashboard.html",
            username=session["username"],
            role=session["role"]
        )

    return redirect(url_for("home"))

# ========================================
# LOGOUT
# ========================================
@app.route('/logout')
def logout():

    session.clear()

    flash("Logged out successfully.", "success")

    return redirect(url_for("home"))

# ========================================
# RUN APP
# ========================================
if __name__ == "__main__":

    app.run(
        debug=True
    )