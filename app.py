from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime, timedelta
import sqlite3
import json

app = Flask(__name__)
CORS(app)  # Enable CORS for frontend-backend communication

# Database setup
DATABASE = 'auto_shop.db'

def get_db_connection():
    """Create a database connection"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Return rows as dictionaries
    return conn

def init_db():
    """Initialize the database with tables"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create bookings table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS bookings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_name TEXT NOT NULL,
            phone TEXT NOT NULL,
            vehicle TEXT NOT NULL,
            service_type TEXT NOT NULL,
            mechanic TEXT NOT NULL,
            description TEXT,
            time_slot TEXT NOT NULL,
            booking_date TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
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
    
    # Insert default mechanics if table is empty
    cursor.execute('SELECT COUNT(*) FROM mechanics')
    if cursor.fetchone()[0] == 0:
        mechanics = [
            ('mike', 'Mike Johnson', 'mike@autoshop.com', '555-0101', 'Engine & Transmission'),
            ('sarah', 'Sarah Williams', 'sarah@autoshop.com', '555-0102', 'Brakes & Suspension'),
            ('david', 'David Brown', 'david@autoshop.com', '555-0103', 'Electrical & Diagnostics')
        ]
        cursor.executemany('''
            INSERT INTO mechanics (mechanic_id, name, email, phone, specialization)
            VALUES (?, ?, ?, ?, ?)
        ''', mechanics)
        conn.commit()
    
    conn.close()
    print("Database initialized successfully!")


# ============================================
# BOOKING ENDPOINTS
# ============================================

@app.route('/api/bookings', methods=['GET'])
def get_bookings():
    """Get all bookings or filter by date/mechanic"""
    date = request.args.get('date')
    mechanic = request.args.get('mechanic')
    status = request.args.get('status')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = 'SELECT * FROM bookings WHERE 1=1'
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
    
    query += ' ORDER BY time_slot ASC'
    
    cursor.execute(query, params)
    bookings = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return jsonify({
        'success': True,
        'bookings': bookings,
        'count': len(bookings)
    })


@app.route('/api/bookings', methods=['POST'])
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
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if time slot is already booked
    cursor.execute('''
        SELECT id FROM bookings 
        WHERE time_slot = ? AND booking_date = ? AND status != 'cancelled'
    ''', (data['time_slot'], data['booking_date']))
    
    if cursor.fetchone():
        conn.close()
        return jsonify({
            'success': False,
            'error': 'Time slot already booked'
        }), 409
    
    # Insert the booking
    cursor.execute('''
        INSERT INTO bookings (customer_name, phone, vehicle, service_type, 
                             mechanic, description, time_slot, booking_date, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        data['customer_name'],
        data['phone'],
        data['vehicle'],
        data['service_type'],
        data['mechanic'],
        data.get('description', ''),
        data['time_slot'],
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


# ============================================
# TIME SLOT ENDPOINTS
# ============================================

@app.route('/api/timeslots', methods=['GET'])
def get_available_slots():
    """Get available time slots for a specific date"""
    date = request.args.get('date')
    
    if not date:
        return jsonify({
            'success': False,
            'error': 'Date parameter required'
        }), 400
    
    # Define all possible time slots
    all_slots = [
        '8:00 AM', '9:00 AM', '10:00 AM', '11:00 AM', '12:00 PM',
        '1:00 PM', '2:00 PM', '3:00 PM', '4:00 PM', '5:00 PM'
    ]
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get booked slots for the date
    cursor.execute('''
        SELECT time_slot FROM bookings 
        WHERE booking_date = ? AND status != 'cancelled'
    ''', (date,))
    
    booked_slots = [row['time_slot'] for row in cursor.fetchall()]
    conn.close()
    
    # Build response with availability
    slots = []
    for slot in all_slots:
        slots.append({
            'time': slot,
            'available': slot not in booked_slots
        })
    
    return jsonify({
        'success': True,
        'date': date,
        'slots': slots
    })


# ============================================
# STATISTICS ENDPOINTS
# ============================================

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get statistics for dashboard"""
    date = request.args.get('date')
    
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
            'GET /api/timeslots': 'Get available slots (required: ?date=YYYY-MM-DD)',
            'GET /api/stats': 'Get statistics (optional: ?date=YYYY-MM-DD)',
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
