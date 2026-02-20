import os
import tempfile
import unittest
from unittest import mock

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

    def _create_booking(self, phone='416-555-1212'):
        payload = {
            'customer_mode': 'new',
            'customer_name': 'SMS User',
            'phone': phone,
            'email': 'smsuser@example.com',
            'vehicle': 'Toyota Camry',
            'service_type': 'oil-change',
            'mechanic': 'ajith-mathew',
            'description': 'SMS test booking',
            'time_slot': '8:00 AM',
            'booking_date': '2026-02-20'
        }
        response = self.client.post('/api/bookings', json=payload)
        self.assertEqual(response.status_code, 201)
        return response.get_json()['booking_id']

    def test_booking_creates_customer_and_links_customer_id(self):
        payload = {
            'customer_mode': 'new',
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
            'customer_mode': 'new',
            'customer_name': 'Alex Rider',
            'phone': '555-333-4444',
            'vehicle': 'Honda Civic',
            'service_type': 'inspection',
            'mechanic': 'ajith-mathew',
            'time_slot': '8:00 AM',
            'booking_date': '2026-02-21'
        }
        second_payload = {
            'customer_mode': 'existing',
            'customer_name': 'Alex Rider Updated',
            'phone': '(555)3334444',
            'vehicle': 'Honda Accord',
            'service_type': 'brake-service',
            'mechanic': 'alvin-antony',
            'time_slot': '9:00 AM',
            'booking_date': '2026-02-21'
        }

        first_response = self.client.post('/api/bookings', json=first_payload)
        self.assertEqual(first_response.status_code, 201)

        conn = scheduler_app.get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM customers WHERE normalized_phone = ?', ('5553334444',))
        existing_customer = cursor.fetchone()
        conn.close()

        second_payload['customer_id'] = existing_customer['id']
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
            'customer_mode': 'new',
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

    def test_new_customer_mode_blocks_duplicate_phone(self):
        payload = {
            'customer_mode': 'new',
            'customer_name': 'First User',
            'phone': '555-777-8888',
            'vehicle': 'Toyota Camry',
            'service_type': 'inspection',
            'mechanic': 'ajith-mathew',
            'time_slot': '8:00 AM',
            'booking_date': '2026-02-23'
        }
        self.assertEqual(self.client.post('/api/bookings', json=payload).status_code, 201)

        duplicate_payload = {
            'customer_mode': 'new',
            'customer_name': 'Second User',
            'phone': '(555)777-8888',
            'vehicle': 'Ford Escape',
            'service_type': 'oil-change',
            'mechanic': 'alvin-antony',
            'time_slot': '9:00 AM',
            'booking_date': '2026-02-23'
        }
        response = self.client.post('/api/bookings', json=duplicate_payload)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.get_json()['error'],
            'Customer already exists. Use Existing Customer option.'
        )

    def test_existing_customer_mode_requires_customer_id(self):
        payload = {
            'customer_mode': 'existing',
            'customer_name': 'Missing Link',
            'phone': '555-121-9999',
            'vehicle': 'Mazda CX-5',
            'service_type': 'inspection',
            'mechanic': 'ajith-mathew',
            'time_slot': '11:00 AM',
            'booking_date': '2026-02-24'
        }
        response = self.client.post('/api/bookings', json=payload)
        self.assertEqual(response.status_code, 400)
        self.assertIn('Selected customer does not exist', response.get_json()['error'])




    def test_booking_creation_schedules_confirmation_reminder(self):
        payload = {
            'customer_mode': 'new',
            'customer_name': 'Reminder User',
            'phone': '555-444-6666',
            'email': 'reminder@example.com',
            'vehicle': 'Kia Soul',
            'service_type': 'inspection',
            'mechanic': 'ajith-mathew',
            'time_slot': '9:00 AM',
            'booking_date': '2099-01-05'
        }

        response = self.client.post('/api/bookings', json=payload)
        self.assertEqual(response.status_code, 201)
        booking_id = response.get_json()['booking_id']

        conn = scheduler_app.get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            'SELECT booking_id, reminder_type, channel, status, confirmation_token FROM booking_reminders WHERE booking_id = ?',
            (booking_id,),
        )
        reminder = cursor.fetchone()
        conn.close()

        self.assertIsNotNone(reminder)
        self.assertEqual(reminder['booking_id'], booking_id)
        self.assertEqual(reminder['reminder_type'], 'confirmation')
        self.assertEqual(reminder['channel'], 'sms')
        self.assertEqual(reminder['status'], 'pending')
        self.assertTrue(reminder['confirmation_token'])

    def test_process_and_confirm_reminder_flow(self):
        payload = {
            'customer_mode': 'new',
            'customer_name': 'Confirm User',
            'phone': '555-100-2000',
            'email': 'confirm@example.com',
            'vehicle': 'Hyundai Elantra',
            'service_type': 'oil-change',
            'mechanic': 'ajith-mathew',
            'time_slot': '10:00 AM',
            'booking_date': '2025-01-01'
        }

        create_response = self.client.post('/api/bookings', json=payload)
        self.assertEqual(create_response.status_code, 201)
        booking_id = create_response.get_json()['booking_id']

        process_response = self.client.post('/api/reminders/process')
        self.assertEqual(process_response.status_code, 200)
        process_payload = process_response.get_json()
        self.assertGreaterEqual(process_payload['count'], 1)

        conn = scheduler_app.get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            'SELECT confirmation_token, status FROM booking_reminders WHERE booking_id = ? ORDER BY id DESC LIMIT 1',
            (booking_id,),
        )
        reminder = cursor.fetchone()
        conn.close()

        self.assertEqual(reminder['status'], 'sent')
        confirm_response = self.client.post(
            f'/api/bookings/{booking_id}/confirm',
            json={'token': reminder['confirmation_token']},
        )
        self.assertEqual(confirm_response.status_code, 200)

        conn = scheduler_app.get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT status FROM bookings WHERE id = ?', (booking_id,))
        booking = cursor.fetchone()
        cursor.execute(
            'SELECT status, response_value FROM booking_reminders WHERE booking_id = ? ORDER BY id DESC LIMIT 1',
            (booking_id,),
        )
        updated_reminder = cursor.fetchone()
        conn.close()

        self.assertEqual(booking['status'], 'confirmed')
        self.assertEqual(updated_reminder['status'], 'responded')
        self.assertEqual(updated_reminder['response_value'], 'confirmed')

    def test_send_sms_success_sets_sent_fields(self):
        booking_id = self._create_booking()

        fake_service = mock.Mock()
        fake_service.provider_name = 'twilio'
        fake_service.send_sms.return_value = {
            'provider_message_id': 'SM123456789',
            'raw_status': 'queued',
        }

        with mock.patch.object(scheduler_app, 'get_sms_service', return_value=fake_service):
            response = self.client.post(f'/api/bookings/{booking_id}/send-confirmation-sms', json={})

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload['success'])
        self.assertEqual(payload['status'], 'SENT')
        self.assertEqual(payload['messageSid'], 'SM123456789')

        conn = scheduler_app.get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            '''
            SELECT confirmation_sms_status, confirmation_sms_sent_at, confirmation_sms_provider_message_id,
                   confirmation_sms_last_error, confirmation_sms_attempt_count
            FROM bookings
            WHERE id = ?
            ''',
            (booking_id,),
        )
        booking = cursor.fetchone()
        conn.close()

        self.assertEqual(booking['confirmation_sms_status'], 'SENT')
        self.assertTrue(booking['confirmation_sms_sent_at'])
        self.assertEqual(booking['confirmation_sms_provider_message_id'], 'SM123456789')
        self.assertIsNone(booking['confirmation_sms_last_error'])
        self.assertEqual(booking['confirmation_sms_attempt_count'], 1)

    def test_send_sms_provider_not_configured_uses_safe_error_message(self):
        booking_id = self._create_booking()

        with mock.patch.object(
            scheduler_app,
            'get_sms_service',
            side_effect=scheduler_app.SmsProviderError('PROVIDER_NOT_CONFIGURED', 'SMS provider not configured. Contact administrator.'),
        ):
            response = self.client.post(f'/api/bookings/{booking_id}/send-confirmation-sms', json={})

        self.assertEqual(response.status_code, 503)
        payload = response.get_json()
        self.assertFalse(payload['success'])
        self.assertEqual(payload['errorCode'], 'PROVIDER_NOT_CONFIGURED')
        self.assertEqual(payload['message'], 'SMS service is currently unavailable.')

        conn = scheduler_app.get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            'SELECT confirmation_sms_status, confirmation_sms_last_error FROM bookings WHERE id = ?',
            (booking_id,),
        )
        booking = cursor.fetchone()
        conn.close()

        self.assertEqual(booking['confirmation_sms_status'], 'FAILED')
        self.assertEqual(booking['confirmation_sms_last_error'], 'SMS service is currently unavailable.')

    def test_send_sms_provider_failure_sets_failed_fields(self):
        booking_id = self._create_booking()

        with mock.patch.object(
            scheduler_app,
            'get_sms_service',
            side_effect=scheduler_app.SmsProviderError('PROVIDER_ERROR', 'Unable to send SMS through provider.'),
        ):
            response = self.client.post(f'/api/bookings/{booking_id}/send-confirmation-sms', json={})

        self.assertEqual(response.status_code, 502)
        payload = response.get_json()
        self.assertFalse(payload['success'])
        self.assertEqual(payload['errorCode'], 'PROVIDER_ERROR')

        conn = scheduler_app.get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            'SELECT confirmation_sms_status, confirmation_sms_last_error FROM bookings WHERE id = ?',
            (booking_id,),
        )
        booking = cursor.fetchone()
        conn.close()

        self.assertEqual(booking['confirmation_sms_status'], 'FAILED')
        self.assertEqual(booking['confirmation_sms_last_error'], 'Unable to send SMS through provider.')

    def test_send_sms_invalid_phone_returns_400(self):
        booking_id = self._create_booking(phone='12345')

        response = self.client.post(f'/api/bookings/{booking_id}/send-confirmation-sms', json={})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()['errorCode'], 'INVALID_PHONE')

    def test_send_sms_booking_not_found_returns_404(self):
        response = self.client.post('/api/bookings/99999/send-confirmation-sms', json={})
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.get_json()['errorCode'], 'BOOKING_NOT_FOUND')

    def test_send_sms_mechanic_forbidden_returns_403(self):
        booking_id = self._create_booking()

        mechanic_client = scheduler_app.app.test_client()
        mechanic_client.post(
            '/auth/login',
            data={'email': 'mechanic@autoshop.local', 'password': 'Mechanic123!', 'role': 'mechanic'},
            follow_redirects=False,
        )
        response = mechanic_client.post(f'/api/bookings/{booking_id}/send-confirmation-sms', json={})
        self.assertEqual(response.status_code, 403)

    def test_send_sms_already_sent_without_force_returns_409(self):
        booking_id = self._create_booking()
        conn = scheduler_app.get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE bookings SET confirmation_sms_status = 'SENT', confirmation_sms_sent_at = CURRENT_TIMESTAMP WHERE id = ?",
            (booking_id,),
        )
        conn.commit()
        conn.close()

        response = self.client.post(f'/api/bookings/{booking_id}/send-confirmation-sms', json={})
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.get_json()['errorCode'], 'ALREADY_SENT')

    def test_send_sms_already_sending_returns_409(self):
        booking_id = self._create_booking()
        conn = scheduler_app.get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE bookings SET confirmation_sms_status = 'SENDING' WHERE id = ?", (booking_id,))
        conn.commit()
        conn.close()

        response = self.client.post(f'/api/bookings/{booking_id}/send-confirmation-sms', json={})
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.get_json()['errorCode'], 'ALREADY_SENDING')

    def test_send_sms_force_resend_allows_sent_bookings(self):
        booking_id = self._create_booking()
        conn = scheduler_app.get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE bookings SET confirmation_sms_status = 'SENT', confirmation_sms_sent_at = CURRENT_TIMESTAMP WHERE id = ?",
            (booking_id,),
        )
        conn.commit()
        conn.close()

        fake_service = mock.Mock()
        fake_service.provider_name = 'twilio'
        fake_service.send_sms.return_value = {'provider_message_id': 'SMRESEND', 'raw_status': 'queued'}
        with mock.patch.object(scheduler_app, 'get_sms_service', return_value=fake_service):
            response = self.client.post(
                f'/api/bookings/{booking_id}/send-confirmation-sms',
                json={'forceResend': True},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()['messageSid'], 'SMRESEND')

if __name__ == '__main__':
    unittest.main()
