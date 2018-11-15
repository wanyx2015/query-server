import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for, jsonify, current_app
)
from werkzeug.security import check_password_hash, generate_password_hash

from flaskr.db import get_db

from flask_json import FlaskJSON, JsonError, json_response, as_json

import requests, jwt, datetime, time

bp = Blueprint('auth', __name__, url_prefix='/auth')


def timethis(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        end = time.time()
        print(func.__name__, end-start)
        return result
    return wrapper


# The First View: Register¶

@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None

        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'
        elif db.execute(
            'SELECT id FROM user WHERE username = ?', (username,)
        ).fetchone() is not None:
            error = 'User {} is already registered.'.format(username)

        if error is None:
            db.execute(
                'INSERT INTO user (username, password, count) VALUES (?, ?, ?)',
                (username, generate_password_hash(password), 50)
            )
            db.commit()
            return json_response(note='注册成功', status=True)

            # return redirect(url_for('auth.login'))

        flash(error)

    return json_response(note='注册失败', status=False)
    # return render_template('auth/register.html')

# Login

@bp.route('/login', methods=('GET', 'POST'))
def login():
    print(request.headers)
    print(request.__dict__)
    for row in request.__dict__:
        print(row)
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM user WHERE username = ?', (username,)
        ).fetchone()

        print("userid", user['id'], 'username', user['username'])

        if user is None:
            error = 'Incorrect username.'
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password.'

        if error is None:

            token = jwt.encode({'user': username, 'userid': user['id'], 'count': user['count'], 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes = 5)}, current_app.config['SECRET_KEY'])

            session.clear()
            # session['user_id'] = user['id']
            session['token'] = token

            return jsonify({'token': token.decode('UTF-8')})


            # return redirect(url_for('index'))
            # return json_response(note='登录成功', status=True)

        flash(error)

        return json_response(status_=401, headers_={'WWW-Authorization': 'Basic realm="Login Required"'}, note='登录失败', status=False)
        # return json_response(note='登录失败', status=False)

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()

# Logout

@bp.route('/logout',methods=('GET', 'POST'))
def logout():
    session.clear()
    # return redirect(url_for('index'))
    return json_response(note='登出成功', status=True)

# Require Authentication in Other Views¶

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view


# get all users

@bp.route('/getall', methods=('GET', 'POST'))
def getAllUsers():
    
    data = []
    db = get_db()
    users = db.execute('SELECT id, username, password FROM user'.format(tn='user', cn='username')).fetchall()

    for row in users:
        print(row['id'], row['username'], row['password'])
        data.append({'id': row['id'], 'username': row['username'], 'password': row['password']})

    print(data)
    
    return json_response(note='获取成功', status=True, users=iter(data))