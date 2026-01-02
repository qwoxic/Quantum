from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_file
from flask_socketio import SocketIO, emit, join_room, leave_room
import os
import hashlib
from datetime import datetime
import sqlite3
import threading
import uuid
import pytz
from werkzeug.utils import secure_filename
from functools import wraps

app = Flask(__name__)
app.secret_key = 'quantum_super_secret_2024_change_this'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

UPLOAD_FOLDER = 'data/uploads'
AVATAR_FOLDER = 'data/avatars'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(AVATAR_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

MOSCOW_TZ = pytz.timezone('Europe/Moscow')

def get_moscow_time():
    return datetime.now(MOSCOW_TZ)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

class QuantumDB:
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._init_db()
        return cls._instance
    
    def _init_db(self):
        os.makedirs('data', exist_ok=True)
        self.conn = sqlite3.connect(
            'data/quantum.db',
            check_same_thread=False,
            timeout=30
        )
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA cache_size=-10000")
        self.conn.execute("PRAGMA temp_store=MEMORY")
        self.conn.row_factory = sqlite3.Row
        self._create_tables()
        self._create_indexes()
    
    def _create_tables(self):
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                display_name TEXT NOT NULL,
                online BOOLEAN DEFAULT 0,
                last_seen TIMESTAMP,
                avatar_hash TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS contacts (
                user_id TEXT,
                contact_id TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (user_id, contact_id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                uuid TEXT UNIQUE NOT NULL,
                chat_id TEXT NOT NULL,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                content TEXT NOT NULL,
                content_type TEXT DEFAULT 'text',
                file_path TEXT,
                file_name TEXT,
                is_read BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                delivered_at TIMESTAMP,
                read_at TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blocks (
                blocker_id TEXT,
                blocked_id TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (blocker_id, blocked_id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS settings (
                username TEXT PRIMARY KEY,
                theme TEXT DEFAULT 'light',
                notifications BOOLEAN DEFAULT 1
            )
        ''')
        self.conn.commit()
    
    def _create_indexes(self):
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_messages_chat 
            ON messages(chat_id, created_at DESC)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_messages_unread
            ON messages(receiver_id, is_read, created_at DESC)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_contacts_user
            ON contacts(user_id)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_blocks
            ON blocks(blocker_id, blocked_id)
        ''')
        self.conn.commit()
    
    def add_message(self, chat_id, sender, receiver, content, msg_type='text', file_path=None, file_name=None):
        msg_uuid = os.urandom(16).hex()
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO messages 
            (uuid, chat_id, sender_id, receiver_id, content, content_type, 
             file_path, file_name, created_at, delivered_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        ''', (msg_uuid, chat_id, sender, receiver, content, msg_type, file_path, file_name))
        self.conn.commit()
        return msg_uuid
    
    def get_chat_messages(self, chat_id, limit=100, offset=0):
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT 
                m.uuid as id,
                m.sender_id as sender,
                m.content as message,
                m.content_type as type,
                m.file_name,
                m.is_read,
                strftime('%H:%M', m.created_at) as timestamp,
                m.created_at
            FROM messages m
            WHERE m.chat_id = ?
            ORDER BY m.created_at DESC
            LIMIT ? OFFSET ?
        ''', (chat_id, limit, offset))
        return [dict(row) for row in cursor.fetchall()]
    
    def get_unread_messages(self, user_id, contact_id):
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT 
                uuid as id,
                sender_id as sender,
                content as message,
                content_type as type,
                file_name,
                strftime('%H:%M', created_at) as timestamp
            FROM messages
            WHERE receiver_id = ? 
              AND sender_id = ?
              AND is_read = 0
            ORDER BY created_at ASC
            LIMIT 50
        ''', (user_id, contact_id))
        messages = [dict(row) for row in cursor.fetchall()]
        if messages:
            cursor.execute('''
                UPDATE messages 
                SET is_read = 1, read_at = CURRENT_TIMESTAMP
                WHERE receiver_id = ? 
                  AND sender_id = ?
                  AND is_read = 0
            ''', (user_id, contact_id))
            self.conn.commit()
        return messages
    
    def mark_as_read(self, user_id, contact_id):
        cursor = self.conn.cursor()
        cursor.execute('''
            UPDATE messages 
            SET is_read = 1, read_at = CURRENT_TIMESTAMP
            WHERE receiver_id = ? 
              AND sender_id = ?
              AND is_read = 0
        ''', (user_id, contact_id))
        self.conn.commit()
        return cursor.rowcount
    
    def update_user_online(self, username, online=True):
        cursor = self.conn.cursor()
        cursor.execute('''
            UPDATE users 
            SET online = ?, last_seen = CURRENT_TIMESTAMP
            WHERE username = ?
        ''', (1 if online else 0, username))
        self.conn.commit()
    
    def add_contact(self, user_id, contact_id):
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT OR IGNORE INTO contacts (user_id, contact_id)
                VALUES (?, ?)
            ''', (user_id, contact_id))
            self.conn.commit()
            return True
        except:
            return False
    
    def get_user_contacts(self, username):
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT 
                c.contact_id as id,
                u.display_name as name,
                u.online,
                u.avatar_hash
            FROM contacts c
            LEFT JOIN users u ON c.contact_id = u.username
            WHERE c.user_id = ?
            ORDER BY u.online DESC, u.display_name ASC
        ''', (username,))
        return [dict(row) for row in cursor.fetchall()]
    
    def user_exists(self, username):
        cursor = self.conn.cursor()
        cursor.execute('SELECT 1 FROM users WHERE username = ?', (username,))
        return cursor.fetchone() is not None
    
    def create_user(self, username, password_hash, display_name):
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT INTO users (username, password_hash, display_name, online, last_seen)
                VALUES (?, ?, ?, 1, CURRENT_TIMESTAMP)
            ''', (username, password_hash, display_name))
            cursor.execute('INSERT INTO settings (username) VALUES (?)', (username,))
            self.conn.commit()
            return True
        except:
            return False
    
    def get_user(self, username):
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        row = cursor.fetchone()
        return dict(row) if row else None
    
    def verify_password(self, username, password_hash):
        cursor = self.conn.cursor()
        cursor.execute('SELECT password_hash FROM users WHERE username = ?', (username,))
        row = cursor.fetchone()
        return row and row[0] == password_hash
    
    def close(self):
        if hasattr(self, 'conn'):
            self.conn.close()

db = QuantumDB()

def get_chat_id(user1, user2):
    return f"{min(user1, user2)}_{max(user1, user2)}"

@socketio.on('connect')
def handle_connect():
    if 'username' in session:
        username = session['username']
        db.update_user_online(username, True)
        emit('online_status', {'user': username, 'online': True}, broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    if 'username' in session:
        username = session['username']
        db.update_user_online(username, False)
        emit('online_status', {'user': username, 'online': False}, broadcast=True)

@socketio.on('join_chat')
def handle_join_chat(data):
    contact = data.get('contact')
    if 'username' in session and contact:
        user = session['username']
        chat_id = get_chat_id(user, contact)
        join_room(chat_id)
        db.mark_as_read(user, contact)
        emit('user_typing', {
            'user': user,
            'contact': contact,
            'typing': False
        }, room=get_chat_id(user, contact))

@socketio.on('leave_chat')
def handle_leave_chat(data):
    contact = data.get('contact')
    if 'username' in session and contact:
        user = session['username']
        chat_id = get_chat_id(user, contact)
        leave_room(chat_id)

@socketio.on('send_message')
def handle_send_message(data):
    if 'username' not in session:
        return
    
    sender = session['username']
    contact = data.get('contact', '').strip()
    message = data.get('message', '').strip()
    msg_type = data.get('type', 'text')
    
    if not contact or not message:
        return
    
    cursor = db.conn.cursor()
    cursor.execute('''
        SELECT 1 FROM blocks 
        WHERE (blocker_id = ? AND blocked_id = ?)
           OR (blocker_id = ? AND blocked_id = ?)
    ''', (sender, contact, contact, sender))
    
    if cursor.fetchone():
        emit('message_error', {'error': 'Пользователь заблокирован'}, room=request.sid)
        return
    
    chat_id = get_chat_id(sender, contact)
    message_id = db.add_message(
        chat_id=chat_id,
        sender=sender,
        receiver=contact,
        content=message,
        msg_type=msg_type
    )
    
    message_data = {
        'id': message_id,
        'sender': sender,
        'message': message,
        'type': msg_type,
        'timestamp': get_moscow_time().strftime('%H:%M'),
        'read': False
    }
    
    emit('new_message', message_data, room=chat_id)
    emit('notification', {
        'from': sender,
        'message': message[:50],
        'type': 'message'
    }, room=f"user_{contact}")

@socketio.on('typing')
def handle_typing(data):
    if 'username' in session:
        sender = session['username']
        contact = data.get('contact')
        is_typing = data.get('typing', False)
        if contact:
            emit('user_typing', {
                'user': sender,
                'contact': contact,
                'typing': is_typing
            }, room=get_chat_id(sender, contact))

@socketio.on('read_message')
def handle_read_message(data):
    if 'username' in session:
        user = session['username']
        contact = data.get('contact')
        message_id = data.get('message_id')
        if contact:
            db.mark_as_read(user, contact)
            emit('message_read', {
                'user': user,
                'contact': contact,
                'message_id': message_id
            }, room=get_chat_id(user, contact))

@app.route('/')
@login_required
def index():
    username = session['username']
    db.update_user_online(username, True)
    contacts = db.get_user_contacts(username)
    return render_template('index.html', username=username, contacts=contacts)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if validate_session():
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if not username or not password:
            return render_template('login.html', error='Заполните все поля')
        
        if db.user_exists(username) and db.verify_password(username, hash_password(password)):
            session['username'] = username
            db.update_user_online(username, True)
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error='Неверное имя пользователя или пароль')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if validate_session():
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        name = request.form.get('name', '').strip()
        
        if not username or not password or not name:
            return render_template('register.html', error='Заполните все поля')
        
        if len(username) < 3:
            return render_template('register.html', error='Логин должен быть не менее 3 символов')
        
        if len(password) < 4:
            return render_template('register.html', error='Пароль должен быть не менее 4 символов')
        
        if db.user_exists(username):
            return render_template('register.html', error='Пользователь уже существует')
        
        if db.create_user(username, hash_password(password), name):
            session['username'] = username
            return redirect(url_for('index'))
        else:
            return render_template('register.html', error='Ошибка создания аккаунта')
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    if 'username' in session:
        username = session['username']
        db.update_user_online(username, False)
        session.clear()
    return redirect(url_for('login'))

@app.route('/chat/<contact>')
@login_required
def chat(contact):
    current_user = session['username']
    
    cursor = db.conn.cursor()
    cursor.execute('''
        SELECT 1 FROM contacts 
        WHERE user_id = ? AND contact_id = ?
    ''', (current_user, contact))
    
    if not cursor.fetchone():
        return redirect(url_for('index'))
    
    chat_id = get_chat_id(current_user, contact)
    messages = db.get_chat_messages(chat_id, limit=50)
    
    cursor.execute('''
        SELECT display_name, online FROM users 
        WHERE username = ?
    ''', (contact,))
    contact_info = cursor.fetchone()
    
    return render_template('chat.html',
                         contact=contact,
                         contact_name=contact_info['display_name'] if contact_info else contact,
                         contact_online=bool(contact_info['online']) if contact_info else False,
                         messages=messages,
                         current_user=current_user)

@app.route('/profile')
@login_required
def profile():
    username = session['username']
    db.update_user_online(username, True)
    user_data = db.get_user(username)
    
    cursor = db.conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM contacts WHERE user_id = ?', (username,))
    contacts_count = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM messages WHERE sender_id = ? OR receiver_id = ?', (username, username))
    messages_count = cursor.fetchone()[0]
    
    return render_template('profile.html',
                         username=username,
                         user_data=user_data,
                         contacts_count=contacts_count,
                         messages_count=messages_count)

@app.route('/user_profile/<user_id>')
@login_required
def user_profile(user_id):
    if not db.user_exists(user_id):
        return redirect(url_for('index'))
    
    current_user = session['username']
    db.update_user_online(current_user, True)
    
    user_data = db.get_user(user_id)
    
    cursor = db.conn.cursor()
    cursor.execute('''
        SELECT 1 FROM contacts 
        WHERE user_id = ? AND contact_id = ?
    ''', (current_user, user_id))
    is_contact = cursor.fetchone() is not None
    
    return render_template('user_profile.html',
                         user_id=user_id,
                         user_data=user_data,
                         is_contact=is_contact)

@app.route('/api/send_message', methods=['POST'])
@login_required
def api_send_message():
    current_user = session['username']
    data = request.get_json()
    
    contact = data.get('contact', '').strip()
    message = data.get('message', '').strip()
    
    if not contact or not message:
        return jsonify({'success': False, 'error': 'Пустое сообщение'})
    
    cursor = db.conn.cursor()
    cursor.execute('''
        SELECT 1 FROM blocks 
        WHERE (blocker_id = ? AND blocked_id = ?)
    ''', (current_user, contact))
    
    if cursor.fetchone():
        return jsonify({'success': False, 'error': 'Пользователь заблокирован'})
    
    chat_id = get_chat_id(current_user, contact)
    message_id = db.add_message(
        chat_id=chat_id,
        sender=current_user,
        receiver=contact,
        content=message,
        msg_type='text'
    )
    
    return jsonify({
        'success': True,
        'message_id': message_id,
        'timestamp': get_moscow_time().strftime('%H:%M')
    })

@app.route('/api/get_unread/<contact>')
@login_required
def get_unread_messages(contact):
    current_user = session['username']
    messages = db.get_unread_messages(current_user, contact)
    return jsonify({
        'success': True,
        'messages': messages,
        'count': len(messages)
    })

@app.route('/api/upload_avatar', methods=['POST'])
@login_required
def upload_avatar():
    username = session['username']
    
    if 'avatar' not in request.files:
        return jsonify({'success': False, 'error': 'Файл не найден'})
    
    file = request.files['avatar']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'Файл не выбран'})
    
    file_ext = os.path.splitext(file.filename)[1].lower()
    if file_ext not in ['.jpg', '.jpeg', '.png', '.gif', '.webp']:
        return jsonify({'success': False, 'error': 'Недопустимый формат'})
    
    avatar_hash = hashlib.md5(username.encode()).hexdigest()[:8]
    filename = f"{avatar_hash}{file_ext}"
    filepath = os.path.join(AVATAR_FOLDER, filename)
    
    file.save(filepath)
    
    cursor = db.conn.cursor()
    cursor.execute('UPDATE users SET avatar_hash = ? WHERE username = ?', (filename, username))
    db.conn.commit()
    
    socketio.emit('avatar_updated', {
        'user': username,
        'avatar_url': f'/avatars/{filename}'
    }, broadcast=True)
    
    return jsonify({
        'success': True,
        'avatar_url': f'/avatars/{filename}'
    })

@app.route('/avatars/<filename>')
def get_avatar(filename):
    filepath = os.path.join(AVATAR_FOLDER, filename)
    if os.path.exists(filepath):
        return send_file(filepath, mimetype='image/jpeg')
    return send_file('static/default_avatar.png', mimetype='image/png')

@app.route('/api/contacts')
@login_required
def get_contacts():
    username = session['username']
    db.update_user_online(username, True)
    contacts = db.get_user_contacts(username)
    return jsonify(contacts)

@app.route('/api/search_users')
@login_required
def search_users():
    current_user = session['username']
    query = request.args.get('q', '').lower().strip()
    
    if not query or len(query) < 2:
        return jsonify([])
    
    cursor = db.conn.cursor()
    cursor.execute('''
        SELECT username, display_name, online
        FROM users
        WHERE (LOWER(username) LIKE ? OR LOWER(display_name) LIKE ?)
          AND username != ?
        LIMIT 10
    ''', (f'%{query}%', f'%{query}%', current_user))
    
    results = []
    for row in cursor.fetchall():
        results.append({
            'id': row['username'],
            'name': row['display_name'],
            'online': bool(row['online'])
        })
    
    return jsonify(results)

@app.route('/api/add_contact', methods=['POST'])
@login_required
def add_contact():
    current_user = session['username']
    data = request.get_json()
    
    contact_id = data.get('contact_id', '').strip()
    
    if not contact_id:
        return jsonify({'success': False, 'error': 'Не указан контакт'})
    
    if contact_id == current_user:
        return jsonify({'success': False, 'error': 'Нельзя добавить самого себя'})
    
    if not db.user_exists(contact_id):
        return jsonify({'success': False, 'error': 'Пользователь не найден'})
    
    if db.add_contact(current_user, contact_id):
        return jsonify({'success': True})
    
    return jsonify({'success': False, 'error': 'Контакт уже добавлен'})

@app.route('/api/block_contact/<contact>', methods=['POST'])
@login_required
def block_contact(contact):
    current_user = session['username']
    
    try:
        cursor = db.conn.cursor()
        cursor.execute('DELETE FROM contacts WHERE user_id = ? AND contact_id = ?', (current_user, contact))
        cursor.execute('INSERT OR IGNORE INTO blocks (blocker_id, blocked_id) VALUES (?, ?)', (current_user, contact))
        db.conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': 'Ошибка блокировки'})

@app.route('/api/update_profile', methods=['POST'])
@login_required
def update_profile():
    username = session['username']
    data = request.get_json()
    
    if not data:
        return jsonify({'success': False, 'error': 'No data provided'})
    
    description = data.get('description', '')[:500]
    
    cursor = db.conn.cursor()
    cursor.execute('UPDATE users SET description = ? WHERE username = ?', (description, username))
    db.conn.commit()
    
    return jsonify({'success': True})

@app.route('/api/update_online_status', methods=['POST'])
@login_required
def update_online_status_api():
    username = session['username']
    db.update_user_online(username, True)
    return jsonify({'success': True})

@app.route('/api/get_contact_status/<contact>')
@login_required
def get_contact_status(contact):
    current_user = session['username']
    db.update_user_online(current_user, True)
    
    user_data = db.get_user(contact)
    contact_online = user_data['online'] if user_data else False
    
    return jsonify({
        'success': True,
        'online': contact_online
    })

def validate_session():
    return 'username' in session and db.user_exists(session['username'])

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host='0.0.0.0', port=port)
