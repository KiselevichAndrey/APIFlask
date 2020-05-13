from flask import render_template, redirect, url_for, request, flash
from flask_login import login_user, login_required, logout_user
from werkzeug.security import check_password_hash, generate_password_hash
import re

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

        if login and email:  # Если пользователь ввел и логин и емейл
            flash('Please, enter either login or email')
            return render_template('login.html')

        if login and password:
            user = User.query.filter_by(login=login).first()

            if user and check_password_hash(user.password, password):
                login_user(user)
                # next_page = request.args.get('next')

                # return redirect(next_page)
                return render_template('main.html', user=login, password=password)
            else:
                flash('Login or password is not correct')
                return render_template('login.html')

        if email and password:
            user = User.query.filter_by(email=email).first()

            if user and check_password_hash(user.password, password):
                login_user(user)
                # next_page = request.args.get('next')

                # return redirect(next_page)
                return render_template('main.html', user=email, password=password)
            else:
                flash('Email or password is not correct')
                return render_template('login.html')
    else:  # Ситуация при первичном входе не страницу login
        flash('Please, fill login(email) and password fields')
        return render_template('login.html')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    login = request.form.get('login')
    email = request.form.get('email')
    password = request.form.get('password')
    password2 = request.form.get('password2')
    pattern_login = re.compile('[a-zA-Z0-9_а-щыэ-яА-ЩЫЭ-Я]+$', re.UNICODE)
    # pattern_email = re.compile(r"^[\w\.\+\-]+\@[\w]+\.[az]{2,3}$")
    pattern_email = re.compile(r"([\w\.-]+)@([\w\.-]+)(\.[\w\.]+)")

    if login and email:
        flash('Please, enter either login or email')
        return render_template('register.html')

    if password:
        if len(password) < 8:
            flash('Password characters too few!')
            return redirect(url_for('register'))

    if login:
        if bool(pattern_login.match(login)) is False:
            flash('Login has special characters!')
            return redirect(url_for('register'))
        if request.method == 'POST':
            if not (login or password or password2):
                flash('Please, fill all fields!')
            elif password != password2:
                flash('Passwords are not equal!')
            else:
                hash_pwd = generate_password_hash(password)
                new_user = User(login=login, password=hash_pwd)

                if User.query.filter_by(login=login).first() is not None:  # Пров-ем в БД создан-ли юзер под этим логом
                    flash('A user with this login is already registered!')
                    return redirect(url_for('register'))
                else:
                    db.session.add(new_user)
                    db.session.commit()

                return redirect(url_for('login_page'))

    elif email:
        if bool(pattern_email.match(email)) is False:
            flash('Email has not correct!')
            return redirect(url_for('register'))
        if request.method == 'POST':
            if not (email or password or password2):
                flash('Please, fill all fields!')
            elif password != password2:
                flash('Passwords are not equal!')
            else:
                hash_pwd = generate_password_hash(password)
                new_user = User(email=email, password=hash_pwd)

                if User.query.filter_by(email=email).first() is not None:  # Пров-ем в БД создан-ли юзер под этим мылом
                    flash('A user with this email is already registered!')
                    return redirect(url_for('register'))
                else:
                    db.session.add(new_user)
                    db.session.commit()

                return redirect(url_for('login_page'))

    return render_template('register.html')


@app.route('/logout', methods=['GET', 'POST'])  # Логаут юзера
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
