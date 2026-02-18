# Auto Shop Scheduling Backend API

A Flask-based REST API for managing automotive maintenance shop appointments.

## Features

- ✅ Create, read, update, and delete bookings
- ✅ Manage mechanics and their schedules
- ✅ Check time slot availability
- ✅ Get statistics and dashboard data
- ✅ SQLite database (easy to upgrade to PostgreSQL)
- ✅ CORS enabled for frontend integration

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Run the Server

```bash
python app.py
```

The server will start on `http://localhost:5000`

### 3. Database Initialization

The database is automatically created on first run with:
- `bookings` table
- `mechanics` table
- `time_slots` table
- 3 default mechanics (Mike, Sarah, David)

## API Endpoints

### Bookings

**Get all bookings**
```http
GET /api/bookings
GET /api/bookings?date=2024-03-15
GET /api/bookings?mechanic=mike
GET /api/bookings?status=pending
```

**Create a booking**
```http
POST /api/bookings
Content-Type: application/json

{
  "customer_name": "John Doe",
  "phone": "(555) 123-4567",
  "vehicle": "2020 Toyota Camry",
  "service_type": "oil-change",
  "mechanic": "mike",
  "description": "Customer reports engine noise",
  "time_slot": "9:00 AM",
  "booking_date": "2024-03-15"
}
```

**Get specific booking**
```http
GET /api/bookings/1
```

**Update booking**
```http
PUT /api/bookings/1
Content-Type: application/json

{
  "status": "completed"
}
```

**Cancel booking**
```http
DELETE /api/bookings/1
```

### Mechanics

**Get all mechanics**
```http
GET /api/mechanics
```

**Get mechanic's bookings**
```http
GET /api/mechanics/mike/bookings
GET /api/mechanics/mike/bookings?date=2024-03-15
```

### Time Slots

**Get available time slots**
```http
GET /api/timeslots?date=2024-03-15
GET /api/timeslots?date=2024-03-15&mechanic=mike
GET /api/timeslots   # defaults to today if date is omitted
```

Returns:
```json
{
  "success": true,
  "date": "2024-03-15",
  "slots": [
    {"time": "8:00 AM", "available": true, "remainingCapacity": 2},
    {"time": "9:00 AM", "available": false, "remainingCapacity": 0},
    ...
  ]
}
```

### Statistics

**Get dashboard stats**
```http
GET /api/stats?date=2024-03-15
GET /api/stats   # defaults to today if date is omitted
```

Returns:
```json
{
  "success": true,
  "stats": {
    "today_total": 5,
    "pending": 3,
    "completed": 2
  }
}
```


### Dashboard

**Get bookings + stats + slot availability in one request**
```http
GET /api/dashboard?date=2024-03-15
GET /api/dashboard   # defaults to today if date is omitted
```

Returns:
```json
{
  "success": true,
  "date": "2024-03-15",
  "bookings": [...],
  "stats": {
    "today_total": 5,
    "pending": 3,
    "completed": 2
  },
  "slots": [
    {"time": "8:00 AM", "available": true, "remainingCapacity": 2}
  ]
}
```

## Database Schema

### bookings
- id (PRIMARY KEY)
- customer_name
- phone
- vehicle
- service_type
- mechanic
- description
- time_slot
- booking_date
- status (pending/completed/cancelled)
- created_at

### mechanics
- id (PRIMARY KEY)
- mechanic_id (UNIQUE)
- name
- email
- phone
- specialization

### time_slots
- id (PRIMARY KEY)
- slot_time
- slot_date
- is_available
- booking_id (FOREIGN KEY)

## Connecting Frontend to Backend

Update your frontend HTML file to make API calls:

```javascript
// Example: Create a booking
async function createBooking(bookingData) {
    const response = await fetch('http://localhost:5000/api/bookings', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(bookingData)
    });
    
    const result = await response.json();
    return result;
}

// Example: Get all dashboard data in one request
async function getDashboardData() {
    const today = new Date().toISOString().split('T')[0];
    const response = await fetch(`http://localhost:5000/api/dashboard?date=${today}`);
    const result = await response.json();
    return result;
}
```

## Upgrading to PostgreSQL (Production)

1. Install psycopg2:
```bash
pip install psycopg2-binary
```

2. Update database connection in `app.py`:
```python
import psycopg2
from psycopg2.extras import RealDictCursor

def get_db_connection():
    conn = psycopg2.connect(
        host="localhost",
        database="auto_shop",
        user="your_username",
        password="your_password"
    )
    return conn
```

## Environment Variables (Optional)

Create a `.env` file:
```
FLASK_ENV=development
DATABASE_URL=sqlite:///auto_shop.db
SECRET_KEY=your-secret-key-here
PORT=5000
```

## Testing the API

Use curl or Postman to test endpoints:

```bash
# Health check
curl http://localhost:5000/api/health

# Get all bookings
curl http://localhost:5000/api/bookings

# Create a booking
curl -X POST http://localhost:5000/api/bookings \
  -H "Content-Type: application/json" \
  -d '{
    "customer_name": "John Doe",
    "phone": "555-1234",
    "vehicle": "2020 Honda Civic",
    "service_type": "oil-change",
    "mechanic": "mike",
    "time_slot": "10:00 AM",
    "booking_date": "2024-03-15"
  }'
```

## Error Handling

All responses follow this format:
```json
{
  "success": true/false,
  "message": "...",
  "data": {...}
}
```

Common HTTP status codes:
- 200: Success
- 201: Created
- 400: Bad Request (missing fields)
- 404: Not Found
- 409: Conflict (time slot already booked)
- 500: Server Error

## Next Steps

1. Add user authentication (JWT tokens)
2. Add email/SMS notifications
3. Add payment processing
4. Add customer portal
5. Deploy to cloud (Heroku, AWS, etc.)

## License

MIT License
