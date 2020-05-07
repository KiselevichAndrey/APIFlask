from flask import render_template, redirect, url_for, request, flash
from flask_login import login_user, login_required, logout_user
from werkzeug.security import check_password_hash, generate_password_hash

from sweater import app, db
from sweater.models import User


@app.route('/', methods=['GET'])
def hello_world():
    return render_template('index.html')


@app.route('/main', methods=['GET'])
@login_required
def main():
    return render_template('main.html')


@app.route('/login', methods=['GET', 'POST'])
def login_page():
    login = request.form.get('login')
    email = request.form.get('email')
    password = request.form.get('password')

    if (email and login and password) is not None:  # Проверяем на None (первичный вход на страницу)

        if login and email:
            flash('Please, enter either login or email')
            return render_template('login.html')

        if login and password:
            user = User.query.filter_by(login=login).first()

            if user and check_password_hash(user.password, password):
                login_user(user)

                # next_page = request.args.get('next')

                # return redirect(next_page)
                return redirect('main')
            else:
                flash('Login or password is not correct')
                return render_template('login.html')
        # else:
        #     flash('Please fill login and password fields')
        #     return render_template('login.html')

        if email and password:
            user = User.query.filter_by(email=email).first()

            if user and check_password_hash(user.password, password):
                login_user(user)

                # next_page = request.args.get('next')

                # return redirect(next_page)
                return redirect('main')
            else:
                flash('Email or password is not correct')
                return render_template('login.html')
        # else:
        #     flash('Please fill email and password fields')
        #     return redirect('login')
    else:
        flash('Please, fill login(email) and password fields')
        return render_template('login.html')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    login = request.form.get('login')
    email = request.form.get('email')
    password = request.form.get('password')
    password2 = request.form.get('password2')

    if password:
            if len(password) < 8:
                flash('Password characters too few!')
                return redirect(url_for('register'))

    if login:
        if request.method == 'POST':
            if not (login or password or password2):
                flash('Please, fill all fields!')
            elif password != password2:
                flash('Passwords are not equal!')
            else:
                hash_pwd = generate_password_hash(password)
                new_user = User(login=login, password=hash_pwd)
                db.session.add(new_user)
                db.session.commit()

                return redirect(url_for('login_page'))

    elif email:
        if request.method == 'POST':
            if not (email or password or password2):
                flash('Please, fill all fields!')
            elif password != password2:
                flash('Passwords are not equal!')
            else:
                hash_pwd = generate_password_hash(password)
                new_user = User(email=email, password=hash_pwd)
                db.session.add(new_user)
                db.session.commit()

                return redirect(url_for('login_page'))

    return render_template('register.html')


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('hello_world'))


# @app.after_request
# def redirect_to_signin(response):
#     if response.status_code == 401:
#         return redirect(url_for('login_page') + '?next=' + request.url)
#
#     return response
