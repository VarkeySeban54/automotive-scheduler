from pathlib import Path
import os
import tempfile
import unittest

import app as scheduler_app


class SlotAvailabilityTests(unittest.TestCase):
    def setUp(self):
        self._db_file = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self._db_file.close()
        scheduler_app.DATABASE = self._db_file.name
        scheduler_app.app.config['TESTING'] = True
        scheduler_app.init_db()

        conn = scheduler_app.get_db_connection()
        cursor = conn.cursor()

        cursor.execute('DELETE FROM bookings')
        cursor.execute('DELETE FROM mechanics')
        cursor.execute("DELETE FROM users WHERE role = 'mechanic'")
        cursor.executemany(
            '''
            INSERT INTO mechanics (mechanic_id, name, email, phone, specialization)
            VALUES (?, ?, ?, ?, ?)
            ''',
            [
                ('mike', 'Mike Johnson', 'mike@autoshop.com', '555-0101', 'Engine'),
                ('sarah', 'Sarah Williams', 'sarah@autoshop.com', '555-0102', 'Brakes'),
            ],
        )
        cursor.executemany(
            '''
            INSERT INTO users (email, password_hash, role, name, active, mechanic_id)
            VALUES (?, ?, 'mechanic', ?, ?, ?)
            ''',
            [
                ('mike@autoshop.local', scheduler_app.hash_password('Pwd123!'), 'Mike User', 1, 'mike'),
                ('sarah@autoshop.local', scheduler_app.hash_password('Pwd123!'), 'Sarah User', 1, 'sarah'),
            ],
        )
        conn.commit()
        conn.close()

        self.client = scheduler_app.app.test_client()
        self.client.post(
            '/auth/login',
            data={'email': 'admin@autoshop.local', 'password': 'Admin123!', 'role': 'admin'},
            follow_redirects=False,
        )

    def tearDown(self):
        if os.path.exists(self._db_file.name):
            os.remove(self._db_file.name)

    def _create_booking(self, mechanic, time_slot='8:00 AM', booking_date='2026-02-18', status='pending'):
        conn = scheduler_app.get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            '''
            INSERT INTO bookings (
                customer_name, phone, vehicle, service_type, mechanic,
                description, time_slot, booking_date, status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''',
            (
                f'{mechanic} customer',
                '555-1000',
                'Toyota Camry',
                'oil-change',
                mechanic,
                '',
                time_slot,
                booking_date,
                status,
            ),
        )
        conn.commit()
        conn.close()

    def test_active_mechanic_count_uses_active_mapped_mechanic_users(self):
        conn = scheduler_app.get_db_connection()
        cursor = conn.cursor()
        self.assertEqual(set(scheduler_app.get_active_mechanic_ids(cursor)), {'mike', 'sarah'})

        cursor.execute("UPDATE users SET active = 0 WHERE mechanic_id = 'sarah'")
        conn.commit()
        self.assertEqual(set(scheduler_app.get_active_mechanic_ids(cursor)), {'mike'})
        conn.close()

    def test_slot_full_when_bookings_equal_active_mechanics(self):
        self._create_booking('mike')
        self._create_booking('sarah')

        response = self.client.get('/api/timeslots?date=2026-02-18')
        payload = response.get_json()

        eight_am = next(slot for slot in payload['slots'] if slot['time'] == '8:00 AM')
        self.assertFalse(eight_am['available'])
        self.assertEqual(eight_am['remainingCapacity'], 0)

    def test_cancelled_and_completed_bookings_do_not_consume_capacity(self):
        self._create_booking('mike', status='cancelled')
        self._create_booking('sarah', status='completed')

        response = self.client.get('/api/timeslots?date=2026-02-18')
        payload = response.get_json()
        eight_am = next(slot for slot in payload['slots'] if slot['time'] == '8:00 AM')

        self.assertTrue(eight_am['available'])
        self.assertEqual(eight_am['remainingCapacity'], 2)

    def test_booking_creation_rejects_when_capacity_reached(self):
        payload = {
            'customer_mode': 'new',
            'customer_name': 'One',
            'phone': '555-111-0001',
            'vehicle': 'Toyota Camry',
            'service_type': 'oil-change',
            'mechanic': 'mike',
            'time_slot': '8:00 AM',
            'booking_date': '2026-02-20',
        }
        self.assertEqual(self.client.post('/api/bookings', json=payload).status_code, 201)

        payload['customer_name'] = 'Two'
        payload['phone'] = '555-111-0002'
        payload['mechanic'] = 'sarah'
        self.assertEqual(self.client.post('/api/bookings', json=payload).status_code, 201)

        payload['customer_name'] = 'Three'
        payload['phone'] = '555-111-0003'
        payload['mechanic'] = 'mike'
        third = self.client.post('/api/bookings', json=payload)
        self.assertEqual(third.status_code, 409)
        self.assertEqual(third.get_json()['error'], 'No slots available for this time. Please select another time.')

    def test_admin_ui_marks_unavailable_slots_as_disabled(self):
        html = Path('index.html').read_text(encoding='utf-8')
        legacy_html = Path('admin_scheduling_panel.html').read_text(encoding='utf-8')

        self.assertIn("const API_BASE_URL = '/api';", html)
        self.assertIn('function renderTimeSlots(slots)', html)
        self.assertIn("slotDiv.className = `time-slot ${!slot.available ? 'booked' : ''}`;", html)
        self.assertIn('legacy entry point', legacy_html)


if __name__ == '__main__':
    unittest.main()
