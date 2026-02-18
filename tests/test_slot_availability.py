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
        conn.commit()
        conn.close()

        self.client = scheduler_app.app.test_client()

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

    def test_slot_full_when_bookings_equal_total_mechanics(self):
        self._create_booking('mike')
        self._create_booking('sarah')

        response = self.client.get('/api/timeslots?date=2026-02-18')
        payload = response.get_json()

        eight_am = next(slot for slot in payload['slots'] if slot['time'] == '8:00 AM')
        self.assertFalse(eight_am['available'])
        self.assertEqual(eight_am['remainingCapacity'], 0)

    def test_slot_has_remaining_capacity_and_mechanic_filter(self):
        self._create_booking('mike')

        response = self.client.get('/api/timeslots?date=2026-02-18')
        payload = response.get_json()
        eight_am = next(slot for slot in payload['slots'] if slot['time'] == '8:00 AM')

        self.assertTrue(eight_am['available'])
        self.assertEqual(eight_am['remainingCapacity'], 1)

        busy_mechanic_response = self.client.get('/api/timeslots?date=2026-02-18&mechanic=mike')
        busy_payload = busy_mechanic_response.get_json()
        busy_eight_am = next(slot for slot in busy_payload['slots'] if slot['time'] == '8:00 AM')

        self.assertFalse(busy_eight_am['available'])
        self.assertEqual(busy_eight_am['remainingCapacity'], 0)

        free_mechanic_response = self.client.get('/api/timeslots?date=2026-02-18&mechanic=sarah')
        free_payload = free_mechanic_response.get_json()
        free_eight_am = next(slot for slot in free_payload['slots'] if slot['time'] == '8:00 AM')

        self.assertTrue(free_eight_am['available'])
        self.assertEqual(free_eight_am['remainingCapacity'], 1)

    def test_admin_ui_marks_unavailable_slots_as_disabled(self):
        html = Path('admin_scheduling_panel.html').read_text(encoding='utf-8')

        self.assertIn('const SLOT_MINUTES = 30;', html)
        self.assertIn('function renderDayScheduleGrid(bookings, slots)', html)
        self.assertIn('timeline-slot-row fully-booked', html)

    def test_back_end_uses_30_minute_slot_generation(self):
        self.assertEqual(scheduler_app.SLOT_MINUTES, 30)
        self.assertEqual(scheduler_app.DAY_START, '08:00')
        self.assertEqual(scheduler_app.DAY_END, '18:00')
        self.assertIn('8:30 AM', scheduler_app.ALL_TIME_SLOTS)
        self.assertEqual(scheduler_app.ALL_TIME_SLOTS[0], '8:00 AM')
        self.assertEqual(scheduler_app.ALL_TIME_SLOTS[-1], '5:30 PM')

    def test_init_db_seeds_admin_panel_default_mechanics(self):
        conn = scheduler_app.get_db_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM mechanics')
        conn.commit()
        conn.close()

        scheduler_app.init_db()

        conn = scheduler_app.get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT mechanic_id FROM mechanics ORDER BY mechanic_id')
        mechanic_ids = [row['mechanic_id'] for row in cursor.fetchall()]
        conn.close()

        self.assertEqual(mechanic_ids, ['ajith-mathew', 'alvin-antony'])


if __name__ == '__main__':
    unittest.main()
