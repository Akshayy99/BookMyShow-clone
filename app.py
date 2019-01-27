from flask import Flask, render_template, url_for,request, redirect, flash, session,logging
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
import sqlite3
from functools import wraps
from flask_login import LoginManager, login_required
from flask.ext.admin import BaseView, expose
from wtforms import DateField, Form
from flask_wtf import Form
from wtforms.validators import Required
from flask.ext.admin.form import widgets

app = Flask(__name__)
login = LoginManager(app)

class DateForm(Form):
    dt = DateField('Pick a Date', format="%m/%d/%Y")

@app.route('/')
def index():
    return render_template('home.html')

@app.route('/seat', methods=['POST'])
def seat():
    dtt = request.form['dtt']
    md = request.form['abc']
    shwd = request.form['efg']
    print(shwd)
    con=sqlite3.connect("seat.db")
    curs=con.cursor()
    curs.execute("SELECT p_id as id, seat_status as status, datet as datet, mv_id as mv_id, show_id as show_id from seat where show_id = ? and mv_id = ? and datet = ?", (shwd, md, dtt))
    var = curs.fetchall()
    n=len(var)
    if n==0:
        for i in range(42):
            curs.execute("INSERT into seat(p_id, seat_status, datet, mv_id, show_id) values(?,?,?,?,?)", (i, "available",dtt, md, shwd))
        con.commit()
    curs.execute("SELECT p_id as id, seat_status as status, datet as datet, mv_id as mv_id, show_id as show_id from seat where show_id = ? and mv_id = ? and datet = ?", (shwd, md, dtt))
    va = curs.fetchall()
    numb = len(va)
    print(numb)
    return render_template('newseat.html', x=var, n=n, va=va, numb=numb, shwd=shwd, md=md, dtt=dtt)

@app.route('/confirm',methods=['GET'])
def confirm():
    occupied = request.args.getlist('seat')
    shwd = request.args.get('shwd')
    md = request.args.get('md')
    dtt = request.args.get('dtt')
    user = session['username']
    print(occupied)
    
    conn = sqlite3.connect("seat.db")
    cur = conn.cursor()
 

    for i in occupied:
        cur.execute("UPDATE seat set seat_status='occupied' WHERE p_id = ? and mv_id = ? and show_id = ? and datet = ?", (i, md, shwd, dtt))
        cur.execute("INSERT into bookings(usr_id, mov_id, shw_id, datet, seat) values(?,?,?,?,?)", (user, md, shwd, dtt, i))
    
    movie_name = cur.execute("SELECT name from movie where movie_id = ?", md).fetchone()[0]
    conn.commit()
    cur.close()
    return render_template("success.html", user=user, seats=occupied, movie_name=movie_name, shwd=shwd, dtt=dtt)
    
class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    username = StringField('Username', [validators.Length(min=4, max=25)])
    email = StringField('Enail', [validators.Length(min=6, max=50)])
    password = PasswordField('Password', [validators.DataRequired(), validators.EqualTo('confirm', message='Passwords don\'t match')])
    confirm = PasswordField('Confirm Password')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        con=sqlite3.connect("seat.db")
        curso=con.cursor()

        curso.execute("INSERT into userd(name, email, username, password) VALUES(?, ?, ?, ?)", (name, email, username, password))

        con.commit()
        curso.close()

        flash('You are now registered and can log in', 'success')

        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password_candidate = request.form['password']

        cone=sqlite3.connect("seat.db")
        cu=cone.cursor()

        result = cu.execute("SELECT * FROM userd WHERE username = ?", [username])
        v = len(cu.fetchall())

        if v > 0:
            # data = cu.fetchone()
            passwordd = cu.execute("SELECT password FROM userd WHERE username = ?", [username])
            password = cu.fetchone()


            print(sha256_crypt.verify(password_candidate, password[0]))

            if sha256_crypt.verify(password_candidate, password[0]):
                app.logger.info('PASSWORD MATCHED')
                session['logged_in'] = True
                session['username'] = username

                flash('You are now logged in', 'success')
                cnn = sqlite3.connect("seat.db")
                cur=cnn.cursor()

                advarr = cu.execute("SELECT status FROM userd WHERE username=?", [username])
                advar = cu.fetchone()

                print(advar)

                if advar[0] == 'y':
                    return redirect(url_for('admin'))

                else:
                    return redirect(url_for('dashboard'))
            else:
                error = 'Invalid login'
                return render_template('login.html', error=error)
            cu.close()
        else:
            app.logger.info('NO USER')
            error = 'Username not found'
            return render_template('login.html', error=error)

    return render_template('login.html')

def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorised, please login', 'danger')
            return redirect(url_for('login'))
    return wrap


def is_logged_in_admin(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        cone=sqlite3.connect("seat.db")
        cu=cone.cursor()
        username = session['username']
        advarr = cu.execute("SELECT status FROM userd WHERE username=?", [username])
        advar = cu.fetchone()[0]
        if 'logged_in' in session and advar=='y':
            return f(*args, **kwargs)
        else:
            flash('Unauthorised, please login', 'danger')
            return redirect(url_for('dashboard'))
    return wrap


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out', 'success')
    return redirect(url_for('login'))


@app.route('/admin')
@is_logged_in_admin
def admin():
    con=sqlite3.connect("seat.db")
    curs=con.cursor()
    curs.execute("SELECT movie_id as id, name as name, description as description, poster_link as poslink from movie")
    var = curs.fetchall()
    n=len(var)
    return render_template('admin.html', x=var,n=n)


@app.route('/change', methods=['GET', 'POST'])
@is_logged_in_admin
def change():
    if request.method == "GET":
        md = request.args.get('md')
        con=sqlite3.connect("seat.db")
        curs=con.cursor()
        curs.execute("SELECT movie_id as id, name as name, description as description, poster_link as poslink from movie where movie_id = ?", md)
        movie = curs.fetchone()
        return render_template('change.html', movie=movie)

    if request.method == "POST": 
        md  = request.form['md']
        mvn = request.form['mvn']
        mvd = request.form['mvd']
        mvl = request.form['mvl']

        con=sqlite3.connect("seat.db")
        curs=con.cursor()
        curs.execute("SELECT movie_id as id, name as name, description as description, poster_link as poslink from movie")
        var = curs.fetchall()
        n=len(var)
        curs.execute("DELETE FROM seat where mv_id=?", md)
        curs.execute("DELETE FROM show where mv_id=?", md)
        # curs.execute("INSERT INTO show(showtime, mv_id,time_id values(?, ?, ?)", ())
        curs.execute("UPDATE movie SET name = ?, description = ?, poster_link = ? WHERE movie_id = ?", (mvn, mvd, mvl, md))
        for a in request.form:
            if a[0] == 's':
                print(a)
                curs.execute("INSERT into show(mv_id, showtime) values(?,?) ", (md, request.form[a]))
        con.commit()
        curs.close()
        return redirect(url_for('admin'))

@app.route('/dashboard')
@is_logged_in
def dashboard():
    con=sqlite3.connect("seat.db")
    curs=con.cursor()
    curs.execute("SELECT movie_id as id, name as name, description as description, poster_link as poslink from movie")
    var = curs.fetchall()
    n=len(var)
    return render_template('dash.html', x=var,n=n)


@app.route('/time', methods=['GET', 'POST'])
def time():
    pm = request.form['check']
    con=sqlite3.connect("seat.db")
    curs=con.cursor()
    curs.execute("SELECT movie_id as id, name as name, description as description, poster_link as poslink from movie where movie_id=?", pm)
    var = curs.fetchall()
    n=len(var)
    curs.execute("SELECT showtime, mv_id, time_id from show where mv_id=?", pm)
    t = curs.fetchall()
    # num = len(t)
    return render_template('time.html', x=var,n=n, t=t)

# @app.route('/profile', methods=['GET'])
# def profile():
#     username = session['username']
#     con=sqlite3.connect("seat.db")
#     curs=con.cursor()
#     curs.execute("SELECT mov_id as mid, shw_id as sid, datet as datet, seat as seat from bookings where usr_id=?", [username])
#     var = curs.fetchall()
#     n=len(var)
#     return render_template('prof.html', username=username,var=var,n=n)

if __name__ == '__main__':
    app.secret_key='secret123'
    app.run(debug=True)
