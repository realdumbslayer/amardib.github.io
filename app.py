from flask import Flask, render_template, flash, redirect, url_for, session, request
from flask_mysqldb import MySQL
from wtforms import Form, StringField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps

app = Flask(__name__)

# Config MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'learning-platform'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

# init MYSQL
mysql = MySQL(app)

# Your existing routes...

@app.route('/')
def index():
    return render_template('home.html')

#About
@app.route('/about')
def about():
    return render_template('about.html')

#Settings
@app.route('/settings')
def settings():
    return render_template('settings.html')

# Register Form Class
class RegisterForm(Form):
    role = StringField('Role (student/instructor)', validators=[validators.DataRequired()])
    first_name = StringField('First Name', validators=[validators.DataRequired()])
    last_name = StringField('Last Name', validators=[validators.DataRequired()])
    email = StringField('Email', [validators.DataRequired(), validators.Email()])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.Length(min=6, max=25)
    ])

    def validate_email(self, field):
        cursor = mysql.connection.cursor()
        if self.role.data == 'student':
            cursor.execute("SELECT * FROM student WHERE email=%s", (field.data,))
        elif self.role.data == 'instructor':
            cursor.execute("SELECT * FROM instructor WHERE email=%s", (field.data,))
        user = cursor.fetchone()
        cursor.close()
        if user:
            raise validators.ValidationError('Email Already Taken')

# Login Form Class
class LoginForm(Form):
    email = StringField('Email', [validators.DataRequired(), validators.Email()])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.Length(min=6, max=25)
    ])

# Registration Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        role = form.role.data.lower()  # Normalize role to lowercase
        first_name = form.first_name.data
        last_name = form.last_name.data
        email = form.email.data
        password = sha256_crypt.encrypt(str(form.password.data))

        cursor = mysql.connection.cursor()
        if role == 'student':
            cursor.execute("INSERT INTO student (first_name, last_name, email, password) VALUES (%s, %s, %s, %s)",
                           (first_name, last_name, email, password))
            flash('You are now registered as a student and can login', 'success')
        elif role == 'instructor':
            cursor.execute("INSERT INTO instructor (first_name, last_name, email, password) VALUES (%s, %s, %s, %s)",
                           (first_name, last_name, email, password))
            flash('You are now registered as an instructor and can login', 'success')
        else:
            flash('Invalid role. Please specify either "student" or "instructor"', 'danger')
            return redirect(url_for('register'))

        mysql.connection.commit()
        cursor.close()

        return redirect(url_for('login'))

    return render_template('register.html', form=form)

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        email = request.form['email']
        password_correct = request.form['password']

        cursor = mysql.connection.cursor()
        # Check if the user exists as a student
        result = cursor.execute("SELECT * FROM student WHERE email=%s", [email])
        if result > 0:
            data = cursor.fetchone()
            password = data['password']
            if sha256_crypt.verify(password_correct, password):
                session['logged_in'] = True
                session['role'] = 'student'
                session['email'] = email
                session['first_name'] = data['first_name']  # Assuming first name is stored in the 'first_name' column
                session['last_name'] = data['last_name']  # Assuming last name is stored in the 'last_name' column
                flash('You are now logged in as a student', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid login. Please check your email and password', 'danger')
                return redirect(url_for('login'))

        # Check if the user exists as an instructor
        result = cursor.execute("SELECT * FROM instructor WHERE email=%s", [email])
        if result > 0:
            data = cursor.fetchone()
            password_hash = data['password']
            print("Password Hash from Database:", password_hash)  # Debugging statement
            if sha256_crypt.verify(password_correct, password_hash):
                session['logged_in'] = True
                session['role'] = 'instructor'
                session['email'] = email
                session['first_name'] = data['first_name']  # Assuming first name is stored in the 'first_name' column
                session['last_name'] = data['last_name']  # Assuming last name is stored in the 'last_name' column
                flash('You are now logged in as an instructor', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid login. Please check your email and password', 'danger')
                return redirect(url_for('login'))

    return render_template('login.html', form=form)

# Check if user logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('login'))
    return wrap

# Logout
@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))

# Dashboard Route
@app.route('/dashboard')
def dashboard():
    if 'logged_in' in session:
        if session['role'] == 'student':
            return render_template('dashboard.html')
        elif session['role'] == 'instructor':
            return render_template('dashboard.html')
    else:
        flash('Unauthorized access. Please login', 'danger')
        return redirect(url_for('login'))


#########################Create Class ################################
# Classes Route
@app.route('/classes')
def classes():
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM classes")
    data = cursor.fetchall()
    cursor.close()

    return render_template('classes.html', classes=data, instructor_first_name=session.get('first_name'), instructor_last_name=session.get('last_name'))

# Insert Route
@app.route('/insert', methods=['GET', 'POST'])
def insert():
    if request.method == "POST":
        flash("Data Inserted Successfully!")
        classname = request.form['classname']
        classcode = request.form['classcode']
        classsection=request.form['classsection']

        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO classes (classname, classcode, classsection) VALUES (%s,%s,%s)", (classname, classcode,classsection))
        mysql.connection.commit()
        return redirect(url_for('classes'))

# Delete Route
@app.route('/delete/<string:id>', methods=['GET', 'POST'])
def delete(id):
    flash("Record Has Been Deleted Successfully!")
    cursor = mysql.connection.cursor()
    cursor.execute("DELETE FROM classes WHERE id=%s", (id,))
    mysql.connection.commit()
    cursor.close()
    return redirect(url_for('classes'))

# Update Route
@app.route('/update', methods=['POST'])
def update():
    if request.method == 'POST':
        id = request.form['id']
        classname = request.form['classname']
        classcode = request.form['classcode']
        classsection = request.form['classsection']

        cursor = mysql.connection.cursor()
        cursor.execute("UPDATE classes SET classname=%s, classcode=%s, classsection=%s WHERE id=%s", (classname, classcode, classsection, id))
        mysql.connection.commit()
        cursor.close()
        flash("Data Updated Successfully!")
        return redirect(url_for('classes'))

if __name__ == '__main__':
    app.secret_key = 'YasAmar'
    app.run(debug=True)
