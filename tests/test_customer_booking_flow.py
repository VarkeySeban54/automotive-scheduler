import os
import tempfile
import unittest

import app as scheduler_app


class CustomerBookingFlowTests(unittest.TestCase):
    def setUp(self):
        self._db_file = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self._db_file.close()
        scheduler_app.DATABASE = self._db_file.name
        scheduler_app.app.config['TESTING'] = True
        scheduler_app.init_db()

        self.client = scheduler_app.app.test_client()
        self.client.post(
            '/auth/login',
            data={'email': 'admin@autoshop.local', 'password': 'Admin123!', 'role': 'admin'},
            follow_redirects=False,
        )

    def tearDown(self):
        if os.path.exists(self._db_file.name):
            os.remove(self._db_file.name)

    def test_booking_creates_customer_and_links_customer_id(self):
        payload = {
            'customer_name': 'Jane Doe',
            'phone': '(555) 111-2222',
            'email': 'jane@example.com',
            'vehicle': 'Toyota Camry',
            'service_type': 'oil-change',
            'mechanic': 'ajith-mathew',
            'description': 'Routine service',
            'time_slot': '8:00 AM',
            'booking_date': '2026-02-20'
        }

        response = self.client.post('/api/bookings', json=payload)
        self.assertEqual(response.status_code, 201)

        conn = scheduler_app.get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT id, full_name, normalized_phone FROM customers')
        customer = cursor.fetchone()
        cursor.execute('SELECT customer_id, email FROM bookings')
        booking = cursor.fetchone()
        conn.close()

        self.assertIsNotNone(customer)
        self.assertEqual(customer['full_name'], 'Jane Doe')
        self.assertEqual(customer['normalized_phone'], '5551112222')
        self.assertEqual(booking['customer_id'], customer['id'])
        self.assertEqual(booking['email'], 'jane@example.com')

    def test_phone_match_reuses_existing_customer(self):
        first_payload = {
            'customer_name': 'Alex Rider',
            'phone': '555-333-4444',
            'vehicle': 'Honda Civic',
            'service_type': 'inspection',
            'mechanic': 'ajith-mathew',
            'time_slot': '8:00 AM',
            'booking_date': '2026-02-21'
        }
        second_payload = {
            'customer_name': 'Alex Rider Updated',
            'phone': '(555)3334444',
            'vehicle': 'Honda Accord',
            'service_type': 'brake-service',
            'mechanic': 'alvin-antony',
            'time_slot': '9:00 AM',
            'booking_date': '2026-02-21'
        }

        self.assertEqual(self.client.post('/api/bookings', json=first_payload).status_code, 201)
        self.assertEqual(self.client.post('/api/bookings', json=second_payload).status_code, 201)

        conn = scheduler_app.get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) as c FROM customers')
        customer_count = cursor.fetchone()['c']
        cursor.execute('SELECT COUNT(DISTINCT customer_id) as c FROM bookings')
        linked_count = cursor.fetchone()['c']
        conn.close()

        self.assertEqual(customer_count, 1)
        self.assertEqual(linked_count, 1)

    def test_customer_search_and_history_endpoints(self):
        payload = {
            'customer_name': 'History User',
            'phone': '555-987-0000',
            'email': 'history@example.com',
            'vehicle': 'Nissan Altima',
            'service_type': 'engine-diagnostic',
            'mechanic': 'ajith-mathew',
            'description': 'Check engine light',
            'time_slot': '10:00 AM',
            'booking_date': '2026-02-22'
        }
        self.assertEqual(self.client.post('/api/bookings', json=payload).status_code, 201)

        search_response = self.client.get('/api/customers/search?q=987')
        self.assertEqual(search_response.status_code, 200)
        search_payload = search_response.get_json()
        self.assertTrue(search_payload['customers'])
        customer_id = search_payload['customers'][0]['id']

        history_response = self.client.get(f'/api/customers/{customer_id}/history?limit=5')
        self.assertEqual(history_response.status_code, 200)
        history_payload = history_response.get_json()
        self.assertEqual(len(history_payload['history']), 1)
        self.assertEqual(history_payload['history'][0]['service_type'], 'engine-diagnostic')


if __name__ == '__main__':
    unittest.main()
