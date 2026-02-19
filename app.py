from functools import wraps
import os
import sqlite3
import json
import hashlib
import hmac
import secrets

from flask import Flask, request, jsonify, redirect, render_template, session, url_for
from flask_cors import CORS
from datetime import datetime, timedelta

app = Flask(__name__)
CORS(app)  # Enable CORS for frontend-backend communication
app.secret_key = os.environ.get('SECRET_KEY', 'dev-only-secret-change-me')
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.environ.get('SESSION_COOKIE_SECURE', 'false').lower() == 'true',
)

# Database setup
DATABASE = 'auto_shop.db'

SLOT_MINUTES = 30
DAY_START = '08:00'
DAY_END = '18:00'


def _minutes_to_slot_label(total_minutes):
    """Return locale-independent 12-hour slot label from total minutes."""
    hours24 = total_minutes // 60
    minutes = total_minutes % 60
    suffix = 'PM' if hours24 >= 12 else 'AM'
    hours12 = ((hours24 + 11) % 12) + 1
    return f"{hours12}:{minutes:02d} {suffix}"


def _slot_label_to_minutes(label):
    """Parse a slot label like 8:30 AM into total minutes."""
    time_part, suffix = label.split(' ')
    hours_raw, minutes_raw = map(int, time_part.split(':'))
    hours = hours_raw % 12
    if suffix.upper() == 'PM':
        hours += 12
    return hours * 60 + minutes_raw


def generate_time_slots(start_time, end_time, slot_minutes):
    """Build slot metadata between start/end using fixed minute increments."""
    start_dt = datetime.strptime(start_time, '%H:%M')
    end_dt = datetime.strptime(end_time, '%H:%M')
    slots = []

    while start_dt < end_dt:
        slot_minutes_from_midnight = start_dt.hour * 60 + start_dt.minute
        slots.append({
            'minutes': slot_minutes_from_midnight,
            'label': _minutes_to_slot_label(slot_minutes_from_midnight)
        })
        start_dt += timedelta(minutes=slot_minutes)

    return slots


ALL_TIME_SLOT_DETAILS = generate_time_slots(DAY_START, DAY_END, SLOT_MINUTES)
ALL_TIME_SLOTS = [slot['label'] for slot in ALL_TIME_SLOT_DETAILS]

NON_BLOCKING_BOOKING_STATUSES = ('cancelled', 'completed')

DEFAULT_MECHANICS = [
    ('ajith-mathew', 'Ajith Mathew', 'ajith@autoshop.com', '555-0101', 'Engine & Transmission'),
    ('alvin-antony', 'Alvin Antony', 'alvin@autoshop.com', '555-0102', 'Brakes & Suspension')
]

LEGACY_DEFAULT_MECHANIC_IDS = {'mike', 'sarah', 'david'}

ROLE_ADMIN = 'admin'
ROLE_FRONTDESK = 'frontdesk'
ROLE_MECHANIC = 'mechanic'
VALID_ROLES = {ROLE_ADMIN, ROLE_FRONTDESK, ROLE_MECHANIC}

DEFAULT_SYSTEM_USERS = [
    {
        'email': 'admin@autoshop.local',
        'password': 'Admin123!',
        'role': ROLE_ADMIN,
        'name': 'System Admin'
    },
    {
        'email': 'frontdesk@autoshop.local',
        'password': 'Frontdesk123!',
        'role': ROLE_FRONTDESK,
        'name': 'Front Desk'
    },
    {
        'email': 'mechanic@autoshop.local',
        'password': 'Mechanic123!',
        'role': ROLE_MECHANIC,
        'name': 'Lead Mechanic',
        'mechanic_id': 'ajith-mathew'
    },
]

def get_db_connection():
    """Create a database connection"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Return rows as dictionaries
    return conn


def hash_password(plain_password):
    iterations = 600000
    salt = secrets.token_hex(16)
    password_hash = hashlib.pbkdf2_hmac(
        'sha256',
        plain_password.encode('utf-8'),
        salt.encode('utf-8'),
        iterations,
    ).hex()
    return f"pbkdf2_sha256${iterations}${salt}${password_hash}"


def verify_password(plain_password, password_hash):
    if password_hash.startswith('pbkdf2_sha256$'):
        try:
            _, iterations_raw, salt, expected_hash = password_hash.split('$', 3)
            calculated_hash = hashlib.pbkdf2_hmac(
                'sha256',
                plain_password.encode('utf-8'),
                salt.encode('utf-8'),
                int(iterations_raw),
            ).hex()
        except (TypeError, ValueError):
            return False
        return hmac.compare_digest(calculated_hash, expected_hash)

    # Legacy fallback for deployments that already have crypt hashes.
    try:
        import crypt
    except ImportError:
        return False
    return crypt.crypt(plain_password, password_hash) == password_hash


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get('user_id'):
            if request.path.startswith('/api/'):
                return jsonify({'success': False, 'error': 'Authentication required'}), 401
            return redirect(url_for('login_page'))
        return func(*args, **kwargs)
    return wrapper


def roles_required(*allowed_roles):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not session.get('user_id'):
                if request.path.startswith('/api/'):
                    return jsonify({'success': False, 'error': 'Authentication required'}), 401
                return redirect(url_for('login_page'))

            if session.get('role') not in allowed_roles:
                if request.path.startswith('/api/'):
                    return jsonify({'success': False, 'error': 'Forbidden'}), 403

                user_role = session.get('role')
                if user_role == ROLE_MECHANIC:
                    return redirect('/mechanic/dashboard')
                return redirect('/admin/dashboard')

            return func(*args, **kwargs)

        return wrapper

    return decorator

def init_db():
    """Initialize the database with tables"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            phone_number TEXT NOT NULL,
            normalized_phone TEXT,
            email TEXT,
            normalized_email TEXT,
            address TEXT,
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute("PRAGMA table_info(customers)")
    customer_columns = {row['name'] for row in cursor.fetchall()}
    if 'normalized_phone' not in customer_columns:
        cursor.execute("ALTER TABLE customers ADD COLUMN normalized_phone TEXT")
    if 'normalized_email' not in customer_columns:
        cursor.execute("ALTER TABLE customers ADD COLUMN normalized_email TEXT")
    if 'address' not in customer_columns:
        cursor.execute("ALTER TABLE customers ADD COLUMN address TEXT")
    if 'notes' not in customer_columns:
        cursor.execute("ALTER TABLE customers ADD COLUMN notes TEXT")
    if 'updated_at' not in customer_columns:
        cursor.execute("ALTER TABLE customers ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP")

    # Create bookings table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS bookings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER,
            customer_name TEXT NOT NULL,
            phone TEXT NOT NULL,
            email TEXT,
            vehicle TEXT NOT NULL,
            service_type TEXT NOT NULL,
            mechanic TEXT NOT NULL,
            description TEXT,
            time_slot TEXT NOT NULL,
            duration_minutes INTEGER DEFAULT 30,
            selected_slots TEXT,
            booking_date TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (customer_id) REFERENCES customers(id)
        )
    ''')

    cursor.execute("PRAGMA table_info(bookings)")
    booking_columns = {row['name'] for row in cursor.fetchall()}
    if 'duration_minutes' not in booking_columns:
        cursor.execute("ALTER TABLE bookings ADD COLUMN duration_minutes INTEGER DEFAULT 30")
    if 'selected_slots' not in booking_columns:
        cursor.execute("ALTER TABLE bookings ADD COLUMN selected_slots TEXT")
    if 'customer_id' not in booking_columns:
        cursor.execute("ALTER TABLE bookings ADD COLUMN customer_id INTEGER")
    if 'email' not in booking_columns:
        cursor.execute("ALTER TABLE bookings ADD COLUMN email TEXT")

    cursor.execute('SELECT id, phone_number, email FROM customers')
    for row in cursor.fetchall():
        normalized_phone = _normalize_phone(row['phone_number'])
        normalized_email = _sanitize_email(row['email']) if row['email'] else None
        cursor.execute(
            'UPDATE customers SET normalized_phone = ?, normalized_email = ? WHERE id = ?',
            (normalized_phone, normalized_email or None, row['id'])
        )

    cursor.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_customers_normalized_phone ON customers(normalized_phone)')
    cursor.execute('''
        CREATE UNIQUE INDEX IF NOT EXISTS idx_customers_normalized_email
        ON customers(normalized_email)
        WHERE normalized_email IS NOT NULL
    ''')
    
    # Create mechanics table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS mechanics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mechanic_id TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            email TEXT,
            phone TEXT,
            specialization TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'frontdesk', 'mechanic')),
            name TEXT NOT NULL,
            active INTEGER DEFAULT 1,
            mechanic_id TEXT
        )
    ''')

    cursor.execute("PRAGMA table_info(users)")
    user_columns = {row['name'] for row in cursor.fetchall()}
    if 'mechanic_id' not in user_columns:
        cursor.execute("ALTER TABLE users ADD COLUMN mechanic_id TEXT")
    
    # Create time_slots table to track availability
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS time_slots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            slot_time TEXT NOT NULL,
            slot_date TEXT NOT NULL,
            is_available INTEGER DEFAULT 1,
            booking_id INTEGER,
            FOREIGN KEY (booking_id) REFERENCES bookings(id)
        )
    ''')
    
    conn.commit()
    
    # Insert/migrate default mechanics to match the admin panel's configured mechanics.
    cursor.execute('SELECT mechanic_id FROM mechanics')
    current_mechanics = {row['mechanic_id'] for row in cursor.fetchall()}

    if not current_mechanics:
        cursor.executemany('''
            INSERT INTO mechanics (mechanic_id, name, email, phone, specialization)
            VALUES (?, ?, ?, ?, ?)
        ''', DEFAULT_MECHANICS)
        conn.commit()
    elif current_mechanics == LEGACY_DEFAULT_MECHANIC_IDS:
        cursor.execute('''
            SELECT COUNT(*) as count FROM bookings WHERE mechanic IN (?, ?, ?)
        ''', tuple(LEGACY_DEFAULT_MECHANIC_IDS))
        legacy_booking_count = cursor.fetchone()['count']

        if legacy_booking_count == 0:
            cursor.execute('DELETE FROM mechanics')
            cursor.executemany('''
                INSERT INTO mechanics (mechanic_id, name, email, phone, specialization)
                VALUES (?, ?, ?, ?, ?)
            ''', DEFAULT_MECHANICS)
            conn.commit()

    cursor.execute('SELECT COUNT(*) as count FROM users')
    existing_user_count = cursor.fetchone()['count']
    if existing_user_count == 0:
        for user in DEFAULT_SYSTEM_USERS:
            cursor.execute(
                '''
                INSERT INTO users (email, password_hash, role, name, active, mechanic_id)
                VALUES (?, ?, ?, ?, 1, ?)
                ''',
                (
                    user['email'],
                    hash_password(user['password']),
                    user['role'],
                    user['name'],
                    user.get('mechanic_id')
                )
            )
        conn.commit()
    
    conn.close()
    print("Database initialized successfully!")


def _normalize_role(role):
    if not role:
        return ''
    return role.strip().lower().replace(' ', '')


def _sanitize_email(email):
    return (email or '').strip().lower()


def _normalize_phone(phone):
    return ''.join(ch for ch in (phone or '') if ch.isdigit())


def _normalize_active(value):
    if isinstance(value, bool):
        return 1 if value else 0
    if isinstance(value, int):
        return 1 if value else 0
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {'1', 'true', 'yes', 'active'}:
            return 1
        if lowered in {'0', 'false', 'no', 'inactive'}:
            return 0
    return None


def _find_customer_by_phone(cursor, phone):
    normalized_phone = _normalize_phone(phone)
    if not normalized_phone:
        return None
    cursor.execute('SELECT * FROM customers WHERE normalized_phone = ?', (normalized_phone,))
    return cursor.fetchone()


def _upsert_customer_for_booking(cursor, data):
    full_name = (data.get('customer_name') or '').strip()
    phone = (data.get('phone') or '').strip()
    email = _sanitize_email(data.get('email')) or None
    address = (data.get('address') or '').strip() or None
    notes = (data.get('customer_notes') or '').strip() or None

    normalized_phone = _normalize_phone(phone)
    if not normalized_phone:
        raise ValueError('Phone number is required')

    existing_customer = _find_customer_by_phone(cursor, phone)
    if existing_customer:
        update_fields = []
        update_params = []
        if full_name and existing_customer['full_name'] != full_name:
            update_fields.append('full_name = ?')
            update_params.append(full_name)
        if email and existing_customer['normalized_email'] != email:
            update_fields.append('email = ?')
            update_params.append(email)
            update_fields.append('normalized_email = ?')
            update_params.append(email)
        if address is not None and existing_customer['address'] != address:
            update_fields.append('address = ?')
            update_params.append(address)
        if notes is not None and existing_customer['notes'] != notes:
            update_fields.append('notes = ?')
            update_params.append(notes)

        if update_fields:
            update_fields.append('updated_at = CURRENT_TIMESTAMP')
            update_params.append(existing_customer['id'])
            cursor.execute(
                f"UPDATE customers SET {', '.join(update_fields)} WHERE id = ?",
                update_params,
            )
        return existing_customer['id']

    cursor.execute(
        '''
        INSERT INTO customers (full_name, phone_number, normalized_phone, email, normalized_email, address, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ''',
        (full_name, phone, normalized_phone, email, email, address, notes),
    )
    return cursor.lastrowid




@app.route('/login', methods=['GET'])
def login_page():
    if session.get('user_id'):
        if session.get('role') == ROLE_MECHANIC:
            return redirect('/mechanic/dashboard')
        return redirect('/admin/dashboard')
    logout_message = None
    if request.args.get('logged_out') == '1':
        logout_message = 'You have been logged out successfully.'
    return render_template('login.html', message=logout_message)


@app.route('/auth/login', methods=['POST'])
def login():
    email = (request.form.get('email') or '').strip().lower()
    password = request.form.get('password') or ''
    selected_role = _normalize_role(request.form.get('role'))

    if not email or not password or selected_role not in VALID_ROLES:
        return render_template('login.html', error='Invalid credentials or role'), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        '''
        SELECT id, email, password_hash, role, name, active, mechanic_id
        FROM users
        WHERE email = ?
        ''',
        (email,)
    )
    user = cursor.fetchone()
    conn.close()

    if not user or not int(user['active']) or not verify_password(password, user['password_hash']) or user['role'] != selected_role:
        return render_template('login.html', error='Invalid credentials or role'), 401

    session.clear()
    session['user_id'] = user['id']
    session['role'] = user['role']
    session['name'] = user['name']
    session['mechanic_id'] = user['mechanic_id']

    if user['role'] == ROLE_MECHANIC:
        return redirect('/mechanic/dashboard')
    return redirect('/admin/dashboard')


@app.route('/logout', methods=['GET'])
def logout():
    session.clear()
    return redirect(url_for('login_page', logged_out='1'))


@app.route('/admin/dashboard', methods=['GET'])
@roles_required(ROLE_ADMIN, ROLE_FRONTDESK)
def admin_dashboard():
    role = session.get('role', ROLE_FRONTDESK)
    role_label = 'Admin' if role == ROLE_ADMIN else 'Front Desk'
    return render_template(
        'admin_dashboard.html',
        user_name=session.get('name', 'User'),
        role=role,
        role_label=role_label,
    )


@app.route('/admin/settings', methods=['GET'])
@roles_required(ROLE_ADMIN)
def admin_settings():
    return jsonify({'success': True, 'message': 'Admin-only settings endpoint'})


@app.route('/user-management', methods=['GET'])
@roles_required(ROLE_ADMIN)
def user_management_page():
    return render_template('user_management.html', user_name=session.get('name', 'Admin'))


@app.route('/admin/users', methods=['GET'])
@roles_required(ROLE_ADMIN)
def admin_users_page():
    return redirect('/user-management')


@app.route('/api/admin/users', methods=['GET'])
@roles_required(ROLE_ADMIN)
def admin_list_users():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, email, role, name, active, mechanic_id
        FROM users
        ORDER BY id ASC
    ''')
    users = [dict(row) for row in cursor.fetchall()]

    cursor.execute('SELECT mechanic_id, name FROM mechanics ORDER BY name ASC')
    mechanics = [dict(row) for row in cursor.fetchall()]

    conn.close()
    return jsonify({'success': True, 'users': users, 'mechanics': mechanics})


@app.route('/api/admin/users', methods=['POST'])
@roles_required(ROLE_ADMIN)
def admin_create_user():
    payload = request.json or {}

    email = _sanitize_email(payload.get('email'))
    password = payload.get('password') or ''
    role = _normalize_role(payload.get('role'))
    name = (payload.get('name') or '').strip()
    active = _normalize_active(payload.get('active'))
    mechanic_id = (payload.get('mechanic_id') or '').strip() or None

    if not email or '@' not in email or not password or not name or role not in VALID_ROLES:
        return jsonify({'success': False, 'error': 'Invalid user data'}), 400

    if len(password) < 8:
        return jsonify({'success': False, 'error': 'Password must be at least 8 characters'}), 400

    if active is None:
        active = 1

    if role != ROLE_MECHANIC:
        mechanic_id = None
    elif not mechanic_id:
        return jsonify({'success': False, 'error': 'Mechanic mapping is required for mechanic role'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    if mechanic_id:
        cursor.execute('SELECT 1 FROM mechanics WHERE mechanic_id = ?', (mechanic_id,))
        if not cursor.fetchone():
            conn.close()
            return jsonify({'success': False, 'error': 'Invalid mechanic_id'}), 400

    try:
        cursor.execute(
            '''
            INSERT INTO users (email, password_hash, role, name, active, mechanic_id)
            VALUES (?, ?, ?, ?, ?, ?)
            ''',
            (email, hash_password(password), role, name, active, mechanic_id)
        )
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'success': False, 'error': 'Email already exists'}), 409

    user_id = cursor.lastrowid
    conn.commit()
    conn.close()

    return jsonify({'success': True, 'message': 'User created', 'user_id': user_id}), 201


@app.route('/api/admin/users/<int:user_id>', methods=['PUT'])
@roles_required(ROLE_ADMIN)
def admin_update_user(user_id):
    payload = request.json or {}

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    existing = cursor.fetchone()
    if not existing:
        conn.close()
        return jsonify({'success': False, 'error': 'User not found'}), 404

    updates = []
    params = []

    if 'name' in payload:
        name = (payload.get('name') or '').strip()
        if not name:
            conn.close()
            return jsonify({'success': False, 'error': 'Name is required'}), 400
        updates.append('name = ?')
        params.append(name)

    if 'email' in payload:
        email = _sanitize_email(payload.get('email'))
        if not email or '@' not in email:
            conn.close()
            return jsonify({'success': False, 'error': 'Invalid email'}), 400
        updates.append('email = ?')
        params.append(email)

    if 'role' in payload:
        role = _normalize_role(payload.get('role'))
        if role not in VALID_ROLES:
            conn.close()
            return jsonify({'success': False, 'error': 'Invalid role'}), 400
        updates.append('role = ?')
        params.append(role)

    if 'active' in payload:
        active = _normalize_active(payload.get('active'))
        if active is None:
            conn.close()
            return jsonify({'success': False, 'error': 'Invalid active value'}), 400
        updates.append('active = ?')
        params.append(active)

    if 'password' in payload and payload.get('password'):
        password = payload.get('password')
        if len(password) < 8:
            conn.close()
            return jsonify({'success': False, 'error': 'Password must be at least 8 characters'}), 400
        updates.append('password_hash = ?')
        params.append(hash_password(password))

    if 'mechanic_id' in payload or 'role' in payload:
        role_after = _normalize_role(payload.get('role')) if 'role' in payload else existing['role']
        mechanic_id = (payload.get('mechanic_id') or '').strip() if 'mechanic_id' in payload else (existing['mechanic_id'] or '')
        mechanic_id = mechanic_id or None

        if role_after != ROLE_MECHANIC:
            mechanic_id = None
        elif mechanic_id:
            cursor.execute('SELECT 1 FROM mechanics WHERE mechanic_id = ?', (mechanic_id,))
            if not cursor.fetchone():
                conn.close()
                return jsonify({'success': False, 'error': 'Invalid mechanic_id'}), 400

        updates.append('mechanic_id = ?')
        params.append(mechanic_id)

    if not updates:
        conn.close()
        return jsonify({'success': False, 'error': 'No fields to update'}), 400

    params.append(user_id)
    try:
        cursor.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = ?", params)
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'success': False, 'error': 'Email already exists'}), 409

    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': 'User updated'})


@app.route('/mechanic/dashboard', methods=['GET'])
@roles_required(ROLE_MECHANIC)
def mechanic_dashboard():
    return render_template(
        'dashboard.html',
        title='Mechanic Dashboard',
        user_name=session.get('name', 'Mechanic'),
        role_label='Mechanic',
        allowed_area='assigned jobs only',
    )


def resolve_target_date(raw_date):
    """Use requested date when provided, otherwise default to today's date."""
    if raw_date:
        return raw_date
    return datetime.now().strftime('%Y-%m-%d')


def build_slot_availability(cursor, date, mechanic_id=None):
    """Build slot availability either for one mechanic or for total shop capacity."""
    cursor.execute('''
        SELECT time_slot, COALESCE(duration_minutes, ?) as duration_minutes, mechanic
        FROM bookings
        WHERE booking_date = ? AND status NOT IN (?, ?)
    ''', (SLOT_MINUTES, date, *NON_BLOCKING_BOOKING_STATUSES))
    active_bookings = [dict(row) for row in cursor.fetchall()]

    def booking_slots(booking):
        start = _slot_label_to_minutes(booking['time_slot'])
        duration = max(int(booking.get('duration_minutes') or SLOT_MINUTES), SLOT_MINUTES)
        labels = []
        for minutes in range(start, start + duration, SLOT_MINUTES):
            label = _minutes_to_slot_label(minutes)
            if label in ALL_TIME_SLOTS:
                labels.append(label)
        return labels

    if mechanic_id:
        booked_slots = set()
        for booking in active_bookings:
            if booking['mechanic'] == mechanic_id:
                booked_slots.update(booking_slots(booking))

        return [
            {
                'time': slot,
                'available': slot not in booked_slots,
                'remainingCapacity': 1 if slot not in booked_slots else 0,
                'available_mechanics': 1 if slot not in booked_slots else 0
            }
            for slot in ALL_TIME_SLOTS
        ]

    cursor.execute('SELECT COUNT(*) as count FROM mechanics')
    mechanic_count = cursor.fetchone()['count']

    booking_counts = {slot: 0 for slot in ALL_TIME_SLOTS}
    for booking in active_bookings:
        for slot in booking_slots(booking):
            booking_counts[slot] = booking_counts.get(slot, 0) + 1

    slots = []
    for slot in ALL_TIME_SLOTS:
        booked_count = booking_counts.get(slot, 0)
        free_count = max(mechanic_count - booked_count, 0)
        slots.append({
            'time': slot,
            'available': free_count > 0,
            'remainingCapacity': free_count,
            'available_mechanics': free_count
        })

    return slots


# ============================================
# BOOKING ENDPOINTS
# ============================================

@app.route('/api/bookings', methods=['GET'])
@roles_required(ROLE_ADMIN, ROLE_FRONTDESK)
def get_bookings():
    """Get all bookings or filter by date/mechanic"""
    date = request.args.get('date')
    mechanic = request.args.get('mechanic')
    status = request.args.get('status')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = '''
        SELECT b.*, c.full_name as customer_full_name, c.phone_number as customer_phone_number,
               c.email as customer_email
        FROM bookings b
        LEFT JOIN customers c ON c.id = b.customer_id
        WHERE 1=1
    '''
    params = []
    
    if date:
        query += ' AND booking_date = ?'
        params.append(date)
    
    if mechanic:
        query += ' AND mechanic = ?'
        params.append(mechanic)
    
    if status:
        query += ' AND status = ?'
        params.append(status)
    
    query += ' ORDER BY b.time_slot ASC'
    
    cursor.execute(query, params)
    bookings = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return jsonify({
        'success': True,
        'bookings': bookings,
        'count': len(bookings)
    })


@app.route('/api/customers/search', methods=['GET'])
@roles_required(ROLE_ADMIN, ROLE_FRONTDESK)
def search_customers():
    query = (request.args.get('q') or '').strip()
    if len(query) < 2:
        return jsonify({'success': True, 'customers': []})

    conn = get_db_connection()
    cursor = conn.cursor()
    normalized_phone = _normalize_phone(query)
    like_term = f"%{query.lower()}%"

    if normalized_phone:
        cursor.execute(
            '''
            SELECT id, full_name, phone_number, email, address, notes, created_at, updated_at
            FROM customers
            WHERE normalized_phone LIKE ?
               OR LOWER(full_name) LIKE ?
               OR LOWER(COALESCE(email, '')) LIKE ?
            ORDER BY updated_at DESC
            LIMIT 12
            ''',
            (f"%{normalized_phone}%", like_term, like_term),
        )
    else:
        cursor.execute(
            '''
            SELECT id, full_name, phone_number, email, address, notes, created_at, updated_at
            FROM customers
            WHERE LOWER(full_name) LIKE ?
               OR LOWER(COALESCE(email, '')) LIKE ?
            ORDER BY updated_at DESC
            LIMIT 12
            ''',
            (like_term, like_term),
        )

    customers = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify({'success': True, 'customers': customers})


@app.route('/api/customers/<int:customer_id>/history', methods=['GET'])
@roles_required(ROLE_ADMIN, ROLE_FRONTDESK, ROLE_MECHANIC)
def customer_service_history(customer_id):
    limit = min(max(int(request.args.get('limit', 8)), 1), 20)
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM customers WHERE id = ?', (customer_id,))
    customer = cursor.fetchone()
    if not customer:
        conn.close()
        return jsonify({'success': False, 'error': 'Customer not found'}), 404

    cursor.execute(
        '''
        SELECT id, booking_date, time_slot, vehicle, service_type, description, status, mechanic
        FROM bookings
        WHERE customer_id = ?
        ORDER BY booking_date DESC, created_at DESC
        LIMIT ?
        ''',
        (customer_id, limit),
    )
    history = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return jsonify({'success': True, 'customer': dict(customer), 'history': history})


@app.route('/api/bookings', methods=['POST'])
@roles_required(ROLE_ADMIN, ROLE_FRONTDESK)
def create_booking():
    """Create a new booking"""
    data = request.json

    # Validate required fields
    required_fields = ['customer_name', 'phone', 'vehicle', 'service_type',
                       'mechanic', 'time_slot', 'booking_date']

    for field in required_fields:
        if field not in data or not data[field]:
            return jsonify({
                'success': False,
                'error': f'Missing required field: {field}'
            }), 400

    duration_minutes = int(data.get('duration_minutes') or SLOT_MINUTES)
    if duration_minutes < SLOT_MINUTES or duration_minutes % SLOT_MINUTES != 0:
        return jsonify({
            'success': False,
            'error': f'duration_minutes must be a multiple of {SLOT_MINUTES}'
        }), 400

    start_minutes = _slot_label_to_minutes(data['time_slot'])
    requested_slots = []
    for minutes in range(start_minutes, start_minutes + duration_minutes, SLOT_MINUTES):
        label = _minutes_to_slot_label(minutes)
        if label not in ALL_TIME_SLOTS:
            return jsonify({
                'success': False,
                'error': 'Selected duration extends beyond working hours'
            }), 400
        requested_slots.append(label)

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        customer_id = _upsert_customer_for_booking(cursor, data)
    except ValueError as exc:
        conn.close()
        return jsonify({'success': False, 'error': str(exc)}), 400
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'success': False, 'error': 'Customer email already exists for another profile'}), 409

    cursor.execute('''
        SELECT time_slot, COALESCE(duration_minutes, ?) as duration_minutes FROM bookings
        WHERE booking_date = ? AND mechanic = ? AND status NOT IN (?, ?)
    ''', (SLOT_MINUTES, data['booking_date'], data['mechanic'], *NON_BLOCKING_BOOKING_STATUSES))

    occupied_slots = set()
    for row in cursor.fetchall():
        row_start = _slot_label_to_minutes(row['time_slot'])
        row_duration = max(int(row['duration_minutes'] or SLOT_MINUTES), SLOT_MINUTES)
        for minutes in range(row_start, row_start + row_duration, SLOT_MINUTES):
            slot_label = _minutes_to_slot_label(minutes)
            if slot_label in ALL_TIME_SLOTS:
                occupied_slots.add(slot_label)

    conflicting = [slot for slot in requested_slots if slot in occupied_slots]
    if conflicting:
        conn.close()
        return jsonify({
            'success': False,
            'error': 'One or more selected slots are already booked for this mechanic',
            'conflicting_slots': conflicting
        }), 409

    selected_slots_json = json.dumps(data.get('selected_slots', requested_slots))

    # Insert the booking
    cursor.execute('''
        INSERT INTO bookings (customer_id, customer_name, phone, email, vehicle, service_type,
                             mechanic, description, time_slot, duration_minutes, selected_slots, booking_date, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        customer_id,
        data['customer_name'],
        data['phone'],
        _sanitize_email(data.get('email')) or None,
        data['vehicle'],
        data['service_type'],
        data['mechanic'],
        data.get('description', ''),
        data['time_slot'],
        duration_minutes,
        selected_slots_json,
        data['booking_date'],
        'pending'
    ))
    
    booking_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return jsonify({
        'success': True,
        'message': 'Booking created successfully',
        'booking_id': booking_id
    }), 201


@app.route('/api/bookings/<int:booking_id>', methods=['GET'])
@roles_required(ROLE_ADMIN, ROLE_FRONTDESK)
def get_booking(booking_id):
    """Get a specific booking by ID"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM bookings WHERE id = ?', (booking_id,))
    booking = cursor.fetchone()
    conn.close()
    
    if booking:
        return jsonify({
            'success': True,
            'booking': dict(booking)
        })
    else:
        return jsonify({
            'success': False,
            'error': 'Booking not found'
        }), 404


@app.route('/api/bookings/<int:booking_id>', methods=['PUT'])
@roles_required(ROLE_ADMIN, ROLE_FRONTDESK)
def update_booking(booking_id):
    """Update a booking (status, time, etc.)"""
    data = request.json
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if booking exists
    cursor.execute('SELECT * FROM bookings WHERE id = ?', (booking_id,))
    if not cursor.fetchone():
        conn.close()
        return jsonify({
            'success': False,
            'error': 'Booking not found'
        }), 404
    
    # Build update query dynamically based on provided fields
    update_fields = []
    params = []
    
    allowed_fields = ['customer_name', 'phone', 'vehicle', 'service_type', 
                      'mechanic', 'description', 'time_slot', 'booking_date', 'status']
    
    for field in allowed_fields:
        if field in data:
            update_fields.append(f'{field} = ?')
            params.append(data[field])
    
    if not update_fields:
        conn.close()
        return jsonify({
            'success': False,
            'error': 'No fields to update'
        }), 400
    
    params.append(booking_id)
    query = f"UPDATE bookings SET {', '.join(update_fields)} WHERE id = ?"
    
    cursor.execute(query, params)
    conn.commit()
    conn.close()
    
    return jsonify({
        'success': True,
        'message': 'Booking updated successfully'
    })


@app.route('/api/bookings/<int:booking_id>', methods=['DELETE'])
@roles_required(ROLE_ADMIN, ROLE_FRONTDESK)
def delete_booking(booking_id):
    """Delete a booking (or mark as cancelled)"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Instead of deleting, mark as cancelled (better for records)
    cursor.execute('''
        UPDATE bookings SET status = 'cancelled' WHERE id = ?
    ''', (booking_id,))
    
    if cursor.rowcount == 0:
        conn.close()
        return jsonify({
            'success': False,
            'error': 'Booking not found'
        }), 404
    
    conn.commit()
    conn.close()
    
    return jsonify({
        'success': True,
        'message': 'Booking cancelled successfully'
    })


# ============================================
# MECHANIC ENDPOINTS
# ============================================

@app.route('/api/mechanics', methods=['GET'])
@roles_required(ROLE_ADMIN, ROLE_FRONTDESK)
def get_mechanics():
    """Get all mechanics"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM mechanics')
    mechanics = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return jsonify({
        'success': True,
        'mechanics': mechanics
    })


@app.route('/api/mechanics/<mechanic_id>/bookings', methods=['GET'])
@roles_required(ROLE_ADMIN, ROLE_FRONTDESK)
def get_mechanic_bookings(mechanic_id):
    """Get all bookings for a specific mechanic"""
    date = request.args.get('date')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = 'SELECT * FROM bookings WHERE mechanic = ?'
    params = [mechanic_id]
    
    if date:
        query += ' AND booking_date = ?'
        params.append(date)
    
    query += ' ORDER BY time_slot ASC'
    
    cursor.execute(query, params)
    bookings = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return jsonify({
        'success': True,
        'mechanic_id': mechanic_id,
        'bookings': bookings,
        'count': len(bookings)
    })



@app.route('/api/mechanic/jobs', methods=['GET'])
@roles_required(ROLE_MECHANIC)
def get_assigned_jobs():
    date = resolve_target_date(request.args.get('date'))
    status = request.args.get('status')

    conn = get_db_connection()
    cursor = conn.cursor()

    query = '''
        SELECT b.*, m.name as mechanic_name
        FROM bookings b
        LEFT JOIN mechanics m ON m.mechanic_id = b.mechanic
        WHERE b.mechanic IS NOT NULL AND TRIM(b.mechanic) != ''
          AND b.booking_date = ?
    '''
    params = [date]

    if status:
        query += ' AND b.status = ?'
        params.append(status)
    else:
        query += " AND b.status IN ('pending', 'in_progress')"

    query += ' ORDER BY booking_date ASC, time_slot ASC'

    cursor.execute(query, params)
    bookings = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return jsonify({'success': True, 'date': date, 'jobs': bookings})


@app.route('/api/mechanic/jobs/<int:booking_id>/status', methods=['PUT'])
@roles_required(ROLE_MECHANIC)
def update_mechanic_job_status(booking_id):
    new_status = (request.json or {}).get('status', '').strip().lower()
    if new_status not in {'pending', 'in_progress', 'completed'}:
        return jsonify({'success': False, 'error': 'Invalid status'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT status, mechanic FROM bookings WHERE id = ?', (booking_id,))
    booking = cursor.fetchone()
    if not booking or not booking['mechanic']:
        conn.close()
        return jsonify({'success': False, 'error': 'Booking not found'}), 404

    current_status = booking['status']
    valid_transitions = {
        'pending': {'in_progress'},
        'in_progress': {'completed'},
        'completed': set(),
        'cancelled': set(),
    }
    if new_status not in valid_transitions.get(current_status, set()):
        conn.close()
        return jsonify({'success': False, 'error': f'Cannot move status from {current_status} to {new_status}'}), 400

    cursor.execute('UPDATE bookings SET status = ? WHERE id = ?', (new_status, booking_id))

    conn.commit()
    conn.close()

    return jsonify({'success': True, 'message': 'Job status updated'})


# ============================================
# TIME SLOT ENDPOINTS
# ============================================

@app.route('/api/timeslots', methods=['GET'])
@roles_required(ROLE_ADMIN, ROLE_FRONTDESK)
def get_available_slots():
    """Get available time slots for a specific date"""
    date = resolve_target_date(request.args.get('date'))
    mechanic = request.args.get('mechanic')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    slots = build_slot_availability(cursor, date, mechanic)
    conn.close()
    
    return jsonify({
        'success': True,
        'date': date,
        'mechanic': mechanic,
        'slots': slots
    })


# ============================================
# STATISTICS ENDPOINTS
# ============================================

@app.route('/api/stats', methods=['GET'])
@roles_required(ROLE_ADMIN, ROLE_FRONTDESK)
def get_stats():
    """Get statistics for dashboard"""
    date = resolve_target_date(request.args.get('date'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Today's bookings
    cursor.execute('''
        SELECT COUNT(*) as count FROM bookings 
        WHERE booking_date = ? AND status != 'cancelled'
    ''', (date,))
    today_count = cursor.fetchone()['count']
    
    # Pending bookings
    cursor.execute('''
        SELECT COUNT(*) as count FROM bookings 
        WHERE booking_date = ? AND status = 'pending'
    ''', (date,))
    pending_count = cursor.fetchone()['count']
    
    # Completed bookings
    cursor.execute('''
        SELECT COUNT(*) as count FROM bookings 
        WHERE booking_date = ? AND status = 'completed'
    ''', (date,))
    completed_count = cursor.fetchone()['count']
    
    conn.close()
    
    return jsonify({
        'success': True,
        'stats': {
            'today_total': today_count,
            'pending': pending_count,
            'completed': completed_count
        }
    })


@app.route('/api/dashboard', methods=['GET'])
@roles_required(ROLE_ADMIN, ROLE_FRONTDESK)
def get_dashboard_data():
    """Get bookings, stats, and time slot availability in one request."""
    date = resolve_target_date(request.args.get('date'))
    mechanic = request.args.get('mechanic')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT b.*, c.full_name as customer_full_name, c.email as customer_email
        FROM bookings b
        LEFT JOIN customers c ON c.id = b.customer_id
        WHERE b.booking_date = ?
        ORDER BY b.time_slot ASC
    ''', (date,))
    bookings = [dict(row) for row in cursor.fetchall()]

    cursor.execute('''
        SELECT COUNT(*) as count FROM bookings
        WHERE booking_date = ? AND status != 'cancelled'
    ''', (date,))
    today_total = cursor.fetchone()['count']

    cursor.execute('''
        SELECT COUNT(*) as count FROM bookings
        WHERE booking_date = ? AND status = 'pending'
    ''', (date,))
    pending = cursor.fetchone()['count']

    cursor.execute('''
        SELECT COUNT(*) as count FROM bookings
        WHERE booking_date = ? AND status = 'completed'
    ''', (date,))
    completed = cursor.fetchone()['count']

    slots = build_slot_availability(cursor, date, mechanic)

    conn.close()

    return jsonify({
        'success': True,
        'date': date,
        'bookings': bookings,
        'stats': {
            'today_total': today_total,
            'pending': pending,
            'completed': completed
        },
        'slots': slots
    })


# ============================================
# HELPER ENDPOINTS
# ============================================

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'success': True,
        'message': 'API is running',
        'timestamp': datetime.now().isoformat()
    })


@app.route('/', methods=['GET'])
def home():
    """Redirect visitors to the login UI."""
    return redirect(url_for('login_page'))


@app.route('/api/docs', methods=['GET'])
def api_docs():
    """API documentation"""
    return jsonify({
        'message': 'Auto Shop Scheduling API',
        'version': '1.0',
        'endpoints': {
            'GET /api/bookings': 'Get all bookings (optional: ?date=YYYY-MM-DD, ?mechanic=id, ?status=pending)',
            'POST /api/bookings': 'Create new booking',
            'GET /api/bookings/:id': 'Get specific booking',
            'PUT /api/bookings/:id': 'Update booking',
            'DELETE /api/bookings/:id': 'Cancel booking',
            'GET /api/mechanics': 'Get all mechanics',
            'GET /api/mechanics/:id/bookings': 'Get mechanic bookings',
            'GET /api/timeslots': 'Get available slots (optional: ?date=YYYY-MM-DD, ?mechanic=id)',
            'GET /api/stats': 'Get statistics (optional: ?date=YYYY-MM-DD)',
            'GET /api/dashboard': 'Get bookings, stats, and slots for one date (optional: ?date=YYYY-MM-DD, ?mechanic=id)',
            'GET /api/health': 'Health check'
        }
    })


if __name__ == '__main__':
    # Initialize database on first run
    init_db()
    
    # Run the Flask app
    print("\n" + "="*50)
    print("🔧 Auto Shop Scheduling API Server")
    print("="*50)
    print("Server running on: http://localhost:5000")
    print("API Documentation: http://localhost:5000")
    print("="*50 + "\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
