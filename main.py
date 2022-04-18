from flask import Flask, render_template, request, session, redirect, send_file, jsonify
from flask_apscheduler import APScheduler
from flask_minify import Minify
from werkzeug.utils import secure_filename
from os import getenv, remove
from os.path import isfile
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from secrets import token_urlsafe
from time import time
from dotenv import load_dotenv
from datetime import datetime
from requests import post
import sqlite3

# Local libraries
from logger import Logger

load_dotenv()

# START CONFIG
CONFIG_DIR = 'userconfigs'
DB = 'data/data.db'
USERFILES_DB = 'data/user.db'
FC_KEY = getenv('FC_KEY')
FC_SITEKEY = getenv('FC_SITEKEY')
# END CONFIG

clients = ['Rise', 'Drip', 'Azura', 'FDP', 'LiquidBounce', 'ZeroDay', 'Tenacity', 'Moon', 'Vape']

app = Flask(__name__)
app.config['SCHEDULER_API_ENABLED'] = True
app.config['SECRET_KEY'] = getenv('SECRET_KEY')

Minify(app=app, html=True, js=True, cssless=True)

scheduler = APScheduler()
scheduler.init_app(app)
scheduler.start()

logger = Logger({
  'global': 'global',
  'file': 'file',
  'auth': 'auth',
  'info': 'info',
  'fine': 'fine',
  'error': 'error'
})

db = sqlite3.connect(DB, check_same_thread=False)
userfiles_db = sqlite3.connect(USERFILES_DB, check_same_thread=False)

ph = PasswordHasher()

cur = userfiles_db.cursor()
cur.execute('CREATE TABLE IF NOT EXISTS configs (id integer primary key, name text, file text, uploader integer, created integer, description text, client integer)')
userfiles_db.commit()

cur = db.cursor()
cur.execute('CREATE TABLE IF NOT EXISTS users (id integer primary key, name text, password text)')
cur.execute('CREATE TABLE IF NOT EXISTS tokens (token text, uid integer, expires integer)')
db.commit()

def get_last_id(cursor, table):
  biggest = -1
  cursor.execute('SELECT id FROM ' + table)
  ids = cursor.fetchall()
  for i in ids:
    as_int = i[0]
    if as_int > biggest: biggest = as_int
  return biggest

def get_last_config_id(cursor):
  return get_last_id(cursor, 'configs')

def get_last_user_id(cursor):
  return get_last_id(cursor, 'users')

@app.route('/upload', methods=["GET"])
def page_upload():
  select = ''
  for i in clients:
    select += f'<option value="{i}">{i}</option>\n'
  return render_template('upload.html', select=select)

def generate_token(n=128):
  return token_urlsafe(n)

def request_new_auth_token(uid:int, timeout=604800):
  # We have already authenticated the user, no need to do it again
  cur = db.cursor()
  token = generate_token()
  expires = int(time()) + timeout
  cur.execute('INSERT INTO tokens VALUES (?, ?, ?)', (token, uid, expires))
  logger.log('auth', f'Token generated for user {str(uid)}. It expires at {expires}.')
  return token

def revoke_auth_token(token:str):
  cur = db.cursor()
  cur.execute('DELETE FROM tokens WHERE token=?', (token,))
  logger.log('auth', f'Token revoked: {token}')
  return 'OK'

def validate_auth_token(token:str):
  cur = db.cursor()
  cur.execute('SELECT * FROM tokens WHERE token=?', (token,))
  data = cur.fetchone()
  if data is None:
    return False
  if time() > data[2]:
    revoke_auth_token(token)
    return False
  logger.log('auth', f'Token successfully validated for {str(data[1])}')
  return data[1]

def get_user_info(uid:int):
  cur = db.cursor()
  cur.execute(f'SELECT name FROM users WHERE id=?', (uid,))
  data = cur.fetchone()
  if data is None: return None
  return data[0]

@app.route('/api/vote', methods=["POST"])
def api_vote():
  if not request.is_json: return 'Not a JSON', 400
  data = request.get_json()
  if not ('id' in data or 'score' in data): return 'Missing parameters', 400
  cur = userfiles_db.cursor()
  id = data['id']
  score = data['score']
  cur.execute('SELECT * FROM configs WHERE id=?', (id,))
  if cur.fetchone() is None: return 'Config not found', 404
  

@app.route('/api/username/<id>', methods=["GET"])
def api_username(id):
  if not id.isdigit(): return 'Not an id', 400
  name = get_user_info(int(id))
  if name is None: return 'Unknown', 404
  return name

@app.route('/api/auth/register', methods=["POST"])
def api_auth_register():
  # Captcha
  resp = post('https://api.friendlycaptcha.com/api/v1/siteverify', json={
    'solution': request.form.get('frc-captcha-solution', '0'),
    'secret': FC_KEY,
    'sitekey': FC_SITEKEY
  })
  print(resp.json())
  if resp.status_code == 200:
    if not resp.json()['success']:
      return 'Invalid captcha', 400
  # Validate data
  name = request.form.get('username', None)
  password = request.form.get('password', None)
  if name is None or password is None:
    return 'Name or password field is empty'
  if not name.isascii():
    return 'Name should be ASCII'
  if len(name) < 2 or len(password) < 4: return 'Input too short', 400
  cur = db.cursor()
  cur.execute('SELECT * FROM users WHERE name=?', (name,))
  dupes = cur.fetchall()
  if len(dupes) > 0:
    return 'Name is taken'
  # Validation passed
  id = get_last_user_id(cur) + 1
  hashed = ph.hash(password)
  # Data is ready and safe
  try:
    cur.execute('INSERT INTO users VALUES (?, ?, ?)', (id, name, hashed,))
  except sqlite3.IntegrityError:
    logger.log('error', f'Duplicate ID error for ID {str(id)}')
    return 'Duplicate ID, try again'
  logger.log('auth', f'New user registered: {name} with ID {str(id)}')
  return redirect('/login')

@app.route('/api/auth/login', methods=["POST"])
def api_auth_login():
  # Checking if everything is ok
  name = request.form.get('username', None)
  password = request.form.get('password', None)
  if name is None or password is None:
    return 'Name or password field is empty', 400
  if not name.isascii():
    return 'Name should be ASCII', 400
  cur = db.cursor()
  cur.execute('SELECT * FROM users WHERE name=?', (name,))
  account = cur.fetchone()
  if account is None:
    return 'Invalid credentials', 400
  hash = account[2]
  uid = account[0]
  try:
    ph.verify(hash, password)
  except VerifyMismatchError:
    return 'Invalid credentials', 400
  #if ph.check_needs_rehash(hash):
    # TODO Rehash the password & commit to the db
  token = request_new_auth_token(uid)
  session['token'] = token
  session['username'] = name
  session['uid'] = uid
  logger.log('auth', f'{name} (id {uid}) logged in')
  return redirect('/')

@app.route('/api/auth/logout', methods=["GET"])
def api_auth_logout():
  uid = validate_auth_token(session['token'])
  if uid is not False:
    revoke_auth_token(session['token'])
    logger.log('auth', f'{str(uid)} logged out')
  else:
    logger.log('auth', '<invalid token> logged out')
  if 'token' in session: session.pop('token', None)
  if 'username' in session: session.pop('username', None)
  if 'uid' in session: session.pop('uid', None)
  return redirect('/')

@app.route('/api/account/change_username', methods=["POST"])
def api_account_change():
  uid = validate_auth_token(session['token'])
  if uid is False:
    return 'Not authorized', 403
  if not request.is_json: return 'Not a JSON', 400
  data = request.get_json()
  new = data['new']
  curr = get_user_info(uid)
  if curr == new:
    return 'Name unchanged', 400
  cur = db.cursor()
  cur.execute('UPDATE users SET name = ? WHERE id = ?', (new, uid))
  return new

@app.route('/api/delete/<id>', methods=["GET"])
def api_delete(id):
  if not 'token' in session: return 'Not authenticated', 401
  cur = userfiles_db.cursor()
  cur.execute('SELECT uploader, file FROM configs WHERE id=?', (id,))
  data = cur.fetchone()
  if data is None: return 'Config not found', 404
  uploader = data[0]
  file = data[1]
  uid = validate_auth_token(session['token'])
  if uid is False:
    return 'Invalid token, please relogin', 401
  if uploader != uid: return 'No permissions', 403
  cur.execute('DELETE FROM configs WHERE id=?', (id,))
  cur.execute('DROP TABLE votes_' + str(id))
  remove(CONFIG_DIR + '/' + file)
  return redirect('/')

@app.route('/api/edit/<id>', methods=["POST"])
def api_edit(id):
  if not 'token' in session: return 'Not authenticated', 401
  cur = userfiles_db.cursor()
  cur.execute('SELECT uploader FROM configs WHERE id=?', (id,))
  uploader = cur.fetchone()
  if uploader is None: return 'Config not found', 404
  uploader = uploader[0]
  uid = validate_auth_token(session['token'])
  if uid is False: return 'Invalid token. Please relogin', 401
  if uid != uploader: return 'No permission', 403
  name = request.form.get('name', 'Unnamed')
  desc = request.form.get('desc', 'No description')
  cur.execute('UPDATE configs SET name=?, description=? WHERE id=?', (name,desc,id,))
  return redirect('/config/'+str(id))

@app.route('/api/upload', methods=["POST"])
def api_upload():
  uid = validate_auth_token(session['token'])
  if uid is False: return 'Not authenticated', 401
  f = request.files['file']
  if f.filename == '': return 'No file', 400
  name = request.form.get('name', 'Unnamed')
  desc = request.form.get('desc', 'No description')
  client = request.form.get('client', 'Undefined')
  if not client in clients: return 'Please select a valid client', 400
  print(desc)
  cur = userfiles_db.cursor()
  last_id = get_last_config_id(cur)
  sec_name = secure_filename(str(last_id+1) + '-' + f.filename)
  f.save(CONFIG_DIR + '/' + sec_name)
  id = last_id + 1
  cur.execute('INSERT INTO configs VALUES (?, ?, ?, ?, ?, ?, ?)', (id, name, sec_name, uid, int(time()), desc, client))
  cur.execute('CREATE TABLE votes_' + str(id) + "(user integer primary key, score integer)")
  logger.log('file', f'New file {sec_name} (id {str(id)}) uploaded by {get_user_info(uid)}')
  return redirect('/config/' + str(id))

@app.route('/api/download/<id>')
def api_download(id):
  cur = userfiles_db.cursor()
  cur.execute('SELECT file FROM configs WHERE id=?', (id,))
  data = cur.fetchone()
  if data is None: return 'Not found', 404
  return send_file(CONFIG_DIR + '/' + data[0], download_name=data[0])

@app.route('/config/edit/<id>', methods=["GET"])
def page_config_edit(id):
  cur = userfiles_db.cursor()
  cur.execute('SELECT * FROM configs WHERE id=?', (id,))
  data = cur.fetchone()
  if data is None: return 'Config not found', 404
  name = data[1]
  created = data[4]
  description = data[5]
  client = data[6]
  created_str = datetime.fromtimestamp(created).strftime('%d.%m.%Y %H:%M:%S')
  return render_template('edit.html', id=str(id), name=name, created=created, description=description, client=client, created_str=created_str)

@app.route('/config/<id>', methods=["GET"])
def page_config(id):
  cur = userfiles_db.cursor()
  cur.execute('SELECT * FROM configs WHERE id=?', (id,))
  data = cur.fetchone()
  if data is None: return 'Config not found', 404
  name = data[1]
  uploader = data[3]
  created = data[4]
  description = data[5]
  client = data[6]
  created_str = datetime.fromtimestamp(created).strftime('%d.%m.%Y %H:%M:%S')
  file_url = f'/api/download/{str(id)}'
  owner = False
  if 'uid' in session:
    if session['uid'] == uploader:
      owner = True
  user = get_user_info(uploader)
  if user is None: user = '(deleted)'
  return render_template('config.html', id=str(id), name=name, user=user, description=description.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('\n', '<br>'), created_str=created_str, file_url=file_url, client=client, owner=owner)

@app.route('/api/configs', methods=["GET"])
def api_configs():
  limit = request.args.get('limit')
  offset = request.args.get('offset')
  if not (limit.isdigit() if isinstance(limit, str) else False):
    limit = 10
  if not (offset.isdigit() if isinstance(offset, str) else False):
    offset = 0
  cur = userfiles_db.cursor()
  cur.execute('SELECT * FROM configs ORDER BY created ASC LIMIT ? OFFSET ?', (limit, offset));
  data = cur.fetchall()
  out = {}
  for i in data:
    user = get_user_info(i[3])
    if user is None: user = '(deleted)'
    out[i[0]] = i[1:] + (user,)
  return jsonify(out)

@app.route('/api/search', methods=["POST"])
def api_search():
  if not request.is_json: return 'Not a JSON', 400
  data = request.get_json()
  cur = userfiles_db.cursor()
  query = data['query']
  if query is not None:
    cur.execute('SELECT * FROM configs ' +
                'WHERE name LIKE "%"||?||"%" ' +
                'OR client LIKE "%"||?||"%" ' +
                'OR description LIKE "%"||?||"%"', (query,query,query))
  else:
    return 'What', 400
  fmt = {}
  for i in cur.fetchall():
    user = get_user_info(i[3])
    if user is None: user = '(deleted)'
    fmt[i[0]] = i[1:] + (user,)
  return jsonify(fmt)

@app.route('/login', methods=["GET"])
def page_login():
  return render_template("login.html")

@app.route('/register', methods=["GET"])
def page_register():
  return render_template("register.html")

@app.route('/search', methods=["GET"])
def page_search():
  return render_template("search.html")

@app.route('/', methods=["GET"])
def page_index():
  if 'token' in session:
    uid = validate_auth_token(session['token'])
    if uid is False:
      return redirect('/api/auth/logout')
    else:
      if session['uid'] != uid:
        return redirect('/api/auth/logout')
  return render_template("index.html")

@scheduler.task('interval', id='save_db', seconds=15, misfire_grace_time=900)
def save_db():
  db.commit()
  userfiles_db.commit()

if __name__ == "__main__":
  app.run(host='0.0.0.0', port=getenv('PORT', 3000))
