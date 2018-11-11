from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for
)
from werkzeug.exceptions import abort

from flaskr.auth import login_required
from flaskr.db import get_db
from flask_json import FlaskJSON, JsonError, json_response, as_json

import requests

bp = Blueprint('query', __name__, url_prefix='/query')


@bp.route('/')
def index():
    db = get_db()
    posts = db.execute(
        'SELECT p.id, title, body, created, author_id, username'
        ' FROM post p JOIN user u ON p.author_id = u.id'
        ' ORDER BY created DESC'
    ).fetchall()
    return render_template('blog/index.html', posts=posts)



@bp.route('/type1', methods=('GET', 'POST'))
@login_required
def type1():
    if request.method == 'POST':
        name = '黄默'
        idcard = '340103198511030017'
        mobile = '15209844817'
        # name = request.form['name']
        # idcard = request.form['idcard']
        # mobile = request.form['mobile']
        # error = None

    url = 'http://211.148.18.173/communication/personal/2016'

    payload={'name': name, 'idcard': idcard, 'mobile': mobile, 'key': '4ae987b67739157051abca0e9b2ba8dd'}
    print(g.user['id'])
    r = requests.post(url, data=payload)
    # return requests.post(url, data=payload).content

    print(r.status_code)
    print(r.content)
    
    if r.status_code == 200:
        db = get_db()
        db.execute('UPDATE user set count = count -1 where id = ?', (g.user['id'],))
        db.commit()
        user = db.execute('select username, count from user where id = ?', (g.user['id'],)).fetchone()

        print(user['username'], user['count'])

        return json_response(note='查询成功', status=True,  count=user['count'], data=str(r.content, encoding = "utf-8"))
        # return r.content

    return json_response(note='查询失败', status=False)
    
    # return json_response(note='查询成功', status=True,  data=iter(r.content))


     