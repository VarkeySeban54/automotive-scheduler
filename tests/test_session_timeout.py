import os
import tempfile
import unittest

import app as scheduler_app


class SessionTimeoutTests(unittest.TestCase):
    def setUp(self):
        self._db_file = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self._db_file.close()
        scheduler_app.DATABASE = self._db_file.name
        scheduler_app.app.config['TESTING'] = True
        scheduler_app.app.config['SESSION_TIMEOUT_MINUTES'] = 30
        scheduler_app.init_db()
        self.client = scheduler_app.app.test_client()

    def tearDown(self):
        if os.path.exists(self._db_file.name):
            os.remove(self._db_file.name)

    def _login_frontdesk(self):
        return self.client.post(
            '/auth/login',
            data={'email': 'frontdesk@autoshop.local', 'password': 'Frontdesk123!', 'role': 'frontdesk'},
            follow_redirects=False,
        )

    def test_unit_inactivity_time_comparison(self):
        self.assertFalse(scheduler_app._is_inactivity_timeout(None, current_ts=5000, timeout_seconds=1800))
        self.assertFalse(scheduler_app._is_inactivity_timeout(3201, current_ts=5000, timeout_seconds=1800))
        self.assertTrue(scheduler_app._is_inactivity_timeout(3199, current_ts=5000, timeout_seconds=1800))

    def test_expired_session_redirects_to_login_with_message(self):
        login_response = self._login_frontdesk()
        self.assertEqual(login_response.status_code, 302)

        with self.client.session_transaction() as flask_session:
            flask_session['last_activity_at'] = scheduler_app._current_timestamp() - (31 * 60)

        response = self.client.get('/admin/dashboard', follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers['Location'].endswith('/login?session_expired=1'))

        login_page = self.client.get('/login?session_expired=1')
        self.assertIn(
            'Your session has expired due to inactivity. Please log in again.',
            login_page.get_data(as_text=True),
        )

        api_client = scheduler_app.app.test_client()
        api_client.post(
            '/auth/login',
            data={'email': 'frontdesk@autoshop.local', 'password': 'Frontdesk123!', 'role': 'frontdesk'},
            follow_redirects=False,
        )
        with api_client.session_transaction() as flask_session:
            flask_session['last_activity_at'] = scheduler_app._current_timestamp() - (31 * 60)

        api_access = api_client.get('/api/dashboard', follow_redirects=False)
        self.assertEqual(api_access.status_code, 401)
        self.assertEqual(
            api_access.get_json()['error'],
            'Your session has expired due to inactivity. Please log in again.',
        )

    def test_activity_resets_last_activity_timestamp(self):
        self._login_frontdesk()

        with self.client.session_transaction() as flask_session:
            flask_session['last_activity_at'] = scheduler_app._current_timestamp() - 60

        self.client.get('/api/dashboard', follow_redirects=False)

        with self.client.session_transaction() as flask_session:
            refreshed = flask_session.get('last_activity_at')

        self.assertIsNotNone(refreshed)
        self.assertGreater(refreshed, scheduler_app._current_timestamp() - 30)


if __name__ == '__main__':
    unittest.main()
