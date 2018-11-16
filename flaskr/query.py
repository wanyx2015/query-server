from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for, jsonify, make_response, Flask, current_app
)
from werkzeug.exceptions import abort

from flaskr.auth import login_required
from flaskr.db import get_db
from flask_json import FlaskJSON, JsonError, json_response, as_json

import requests, jwt, datetime, time, json

from functools import wraps
from Crypto.Hash import SHA256
from binascii import b2a_hex, a2b_hex


url = 'https://crp.chinadep.com/api/p/crp/'
memId = '0000109'
jobId = 'JON20181116000000291'
serialNo = '1201611161916567677531846'
appKey = '02DF41BAAB249FB5F42BB6DB7FFE4A3377AFFDA59C849506EEDA52351E65B0F345'
hash_str = str.encode(memId + serialNo + jobId + appKey)
hash_inst = SHA256.new(hash_str)
digest = hash_inst.digest()
digest_str = b2a_hex(digest)


class MyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (bytes, bytearray)):
            return obj.decode("ASCII") # <- or any other encoding of your choice
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)



def timethis(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        end = time.time()
        print(func.__name__, end-start)
        return result
    return wrapper

def token_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        
        # print(request.headers)
        # print(request.__dict__)
        print(request.form)
        for r in request.form:
            print(r, request.form[r])

        # token = request.args.get('access_token')
        token = request.form['token']

        print('token is', token)
        
        if not token:
            print("token is missing")
            # return jsonify({'message': 'token is missing'}) 403
            return json_response(status_=403, headers_={'message': 'token is missing'})

        
        try:
            data = jwt.decode(token, current_app.config['SECRET_KEY'])
            print(data)
            print(data['user'])

            userid = data['userid']
            g.user = get_db().execute('SELECT * FROM user WHERE id = ?', (userid,)).fetchone()
        
            # if user_id is None:
            #     g.user = None
            # else:
            #     g.user = get_db().execute('SELECT * FROM user WHERE id = ?', (user_id,)).fetchone()

        except:
            print("token is invalid")
            # return jsonify({'message': 'token is invalid'}) 403
            return json_response(status_=403, headers_={'message': 'token is invalid'})


        return func(*args, **kwargs)
    return wrapper


bp = Blueprint('query', __name__, url_prefix='/query')

@bp.route('/type1', methods=('GET', 'POST'))
@timethis
@token_required
def type1():
    
    if request.method == 'POST':
        # name = '黄默'
        # idcard = '340103198511030017'
        # mobile = '15209844817'
        name = request.form['name']
        idcard = request.form['idcard']
        mobile = request.form['mobile']
        # error = None

    url = 'http://211.148.18.173/communication/personal/2016'
    # url = 'http://www.webvep.com'

    payload={'name': name, 'idcard': idcard, 'mobile': mobile, 'key': '4ae987b67739157051abca0e9b2ba8dd'}
    # print(g.user['id'])
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
        content = jsonify(r.content)
        print(content)

        # return json_response(note='查询成功', status=True,  count=user['count'], data=r.content)
        return json_response(note='查询成功', status=True,  count=user['count'], data=str(r.content, encoding = "utf-8"))
        # return r.content
    # return r.content
    # return json_response(note='查询成功', status=True,   data=str(r.content, encoding = "utf-8"))

    return json_response(note='查询失败', status=False)
    
    # return json_response(note='查询成功', status=True,  data=iter(r.content))



@bp.route('/getcount', methods=('GET', 'POST'))
@timethis
@token_required
def getcount():
    db = get_db()
    user = db.execute('select username, count from user where id = ?', (g.user['id'],)).fetchone()

    print(user['username'], user['count'])
    return json_response(note='查询成功', status=True,  count=user['count'], user=user['username'])

    # return json_response(note='查询失败', status=False)
    

@bp.route('/unprotected', methods=('GET', 'POST'))
@timethis
def unprotected():
    return json_response(note='Un-protected', status=True)

@bp.route('/protected', methods=('GET', 'POST'))
@timethis
@token_required
def protected():
    return json_response(note='Protected', status=True)


@bp.route('/login', methods=('GET', 'POST'))
@timethis
def login():
    auth = request.authorization
    print('request:', request)
    print('request.authorization:', request.authorization)

    username = request.form['username']
    password = request.form['password']

    if password == 'password':
        token = jwt.encode({'user': username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes = 10)}, current_app.config['SECRET_KEY'])
        return jsonify({'token': token.decode('UTF-8')})

    return json_response(status_=401, headers_={'WWW-Authorization': 'Basic realm="Login Required"'})





@bp.route('/type2001001', methods=('GET', 'POST'))
@timethis
@token_required
def type2001001():
    
    if request.method == 'POST':
        fullName = request.form['name']
        identityNumber = request.form['idcard']
        # mobile = request.form['mobile']
        # error = None
        data = {
                'pubReqInfo': {'memId': memId,
                            'serialNo': serialNo,
                            'jobId': 'JON20161005000000076',
                            'timeStamp': str(int(time.time())),
                            'authMode': '00',
                            'reqSign': digest_str},
                'busiInfo': {"identityNumber":identityNumber, "name":fullName},
            }

        jsonified = json.dumps(data, cls=MyEncoder)
        print('jsonified', jsonified)
        print(10*'*' + '\n' )
        r = requests.post(url, json.dumps(data, cls=MyEncoder))
        print(r.content)
  

        if r.status_code == 200:
            db = get_db()
            db.execute('UPDATE user set count = count -1 where id = ?', (g.user['id'],))
            db.commit()
            user = db.execute('select username, count from user where id = ?', (g.user['id'],)).fetchone()

            print(user['username'], user['count'])
            content = jsonify(r.content)
            print(content)

            # return json_response(note='查询成功', status=True,  count=user['count'], data=r.content)
            return json_response(note='查询成功', status=True,  count=user['count'], data=str(r.content, encoding = "utf-8"))
            # return r.content


        return json_response(note='查询成功', status=True,  count=user['count'], data=str(r.content, encoding = "utf-8"))

    return json_response(note='查询失败', status=False)
    



@bp.route('/type3001001', methods=('GET', 'POST'))
@timethis
@token_required
def type3001001():
    
    if request.method == 'POST':
        fullName = request.form['name']
        identityNumber = request.form['idcard']
        # mobile = request.form['mobile']
        # error = None
        data = {
                'pubReqInfo': {'memId': memId,
                            'serialNo': serialNo,
                            'jobId': 'JON20161005000000076',
                            'timeStamp': str(int(time.time())),
                            'authMode': '00',
                            'reqSign': digest_str},
                'busiInfo': {"identityNumber":identityNumber, "name":fullName},
            }

        jsonified = json.dumps(data, cls=MyEncoder)
        print('jsonified', jsonified)
        print(10*'*' + '\n' )
        r = requests.post(url, json.dumps(data, cls=MyEncoder))
        print(r.content)
  

        if r.status_code == 200:
            db = get_db()
            db.execute('UPDATE user set count = count -1 where id = ?', (g.user['id'],))
            db.commit()
            user = db.execute('select username, count from user where id = ?', (g.user['id'],)).fetchone()

            print(user['username'], user['count'])
            content = jsonify(r.content)
            print(content)

            # return json_response(note='查询成功', status=True,  count=user['count'], data=r.content)
            return json_response(note='查询成功', status=True,  count=user['count'], data=str(r.content, encoding = "utf-8"))
            # return r.content


        return json_response(note='查询成功', status=True,  count=user['count'], data=str(r.content, encoding = "utf-8"))

    return json_response(note='查询失败', status=False)
    
