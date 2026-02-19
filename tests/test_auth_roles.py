import os
import tempfile
import unittest

import app as scheduler_app


class AuthRoleTests(unittest.TestCase):
    def setUp(self):
        self._db_file = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self._db_file.close()
        scheduler_app.DATABASE = self._db_file.name
        scheduler_app.app.config['TESTING'] = True
        scheduler_app.init_db()
        self.client = scheduler_app.app.test_client()

    def tearDown(self):
        if os.path.exists(self._db_file.name):
            os.remove(self._db_file.name)

    def test_login_page_contains_three_roles(self):
        response = self.client.get('/login')
        html = response.get_data(as_text=True)

        self.assertIn('value="admin"', html)
        self.assertIn('value="frontdesk"', html)
        self.assertIn('value="mechanic"', html)

    def test_admin_and_frontdesk_redirect_to_admin_dashboard(self):
        admin_response = self.client.post(
            '/auth/login',
            data={'email': 'admin@autoshop.local', 'password': 'Admin123!', 'role': 'admin'},
            follow_redirects=False,
        )
        self.assertEqual(admin_response.status_code, 302)
        self.assertTrue(admin_response.headers['Location'].endswith('/admin/dashboard'))

        client = scheduler_app.app.test_client()
        frontdesk_response = client.post(
            '/auth/login',
            data={'email': 'frontdesk@autoshop.local', 'password': 'Frontdesk123!', 'role': 'frontdesk'},
            follow_redirects=False,
        )
        self.assertEqual(frontdesk_response.status_code, 302)
        self.assertTrue(frontdesk_response.headers['Location'].endswith('/admin/dashboard'))

    def test_mechanic_redirects_to_mechanic_dashboard(self):
        response = self.client.post(
            '/auth/login',
            data={'email': 'mechanic@autoshop.local', 'password': 'Mechanic123!', 'role': 'mechanic'},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers['Location'].endswith('/mechanic/dashboard'))

    def test_wrong_role_shows_error(self):
        response = self.client.post(
            '/auth/login',
            data={'email': 'admin@autoshop.local', 'password': 'Admin123!', 'role': 'mechanic'},
            follow_redirects=False,
        )
        html = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 401)
        self.assertIn('Invalid credentials or role', html)

    def test_route_protection_and_logout(self):
        unauth = self.client.get('/api/dashboard', follow_redirects=False)
        self.assertEqual(unauth.status_code, 401)
        self.assertEqual(unauth.get_json()['error'], 'Authentication required')

        self.client.post(
            '/auth/login',
            data={'email': 'frontdesk@autoshop.local', 'password': 'Frontdesk123!', 'role': 'frontdesk'},
            follow_redirects=False,
        )
        forbidden = self.client.get('/admin/settings', follow_redirects=False)
        self.assertEqual(forbidden.status_code, 302)
        self.assertTrue(forbidden.headers['Location'].endswith('/admin/dashboard'))

        logout = self.client.get('/logout', follow_redirects=False)
        self.assertEqual(logout.status_code, 302)
        self.assertTrue(logout.headers['Location'].endswith('/login?logged_out=1'))

        login_page = self.client.get('/login?logged_out=1')
        self.assertEqual(login_page.status_code, 200)
        self.assertIn('You have been logged out successfully.', login_page.get_data(as_text=True))

        after_logout = self.client.get('/api/dashboard', follow_redirects=False)
        self.assertEqual(after_logout.status_code, 401)
        self.assertEqual(after_logout.get_json()['error'], 'Authentication required')

        dashboard_after_logout = self.client.get('/admin/dashboard', follow_redirects=False)
        self.assertEqual(dashboard_after_logout.status_code, 302)
        self.assertTrue(dashboard_after_logout.headers['Location'].endswith('/login'))

    def test_dashboards_render_logout_button_and_user_name(self):
        admin_client = scheduler_app.app.test_client()
        admin_client.post(
            '/auth/login',
            data={'email': 'admin@autoshop.local', 'password': 'Admin123!', 'role': 'admin'},
            follow_redirects=False,
        )
        admin_dashboard = admin_client.get('/admin/dashboard')
        admin_html = admin_dashboard.get_data(as_text=True)
        self.assertEqual(admin_dashboard.status_code, 200)
        self.assertIn('Admin: System Admin', admin_html)
        self.assertIn('href="/logout"', admin_html)

        mechanic_client = scheduler_app.app.test_client()
        mechanic_client.post(
            '/auth/login',
            data={'email': 'mechanic@autoshop.local', 'password': 'Mechanic123!', 'role': 'mechanic'},
            follow_redirects=False,
        )
        mechanic_dashboard = mechanic_client.get('/mechanic/dashboard')
        mechanic_html = mechanic_dashboard.get_data(as_text=True)
        self.assertEqual(mechanic_dashboard.status_code, 200)
        self.assertIn('Mechanic: Lead Mechanic', mechanic_html)
        self.assertIn('href="/logout"', mechanic_html)

    def test_passwords_are_hashed(self):
        conn = scheduler_app.get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT password_hash FROM users WHERE email = ?', ('admin@autoshop.local',))
        row = cursor.fetchone()
        conn.close()

        self.assertIsNotNone(row)
        self.assertNotEqual(row['password_hash'], 'Admin123!')
        self.assertTrue(row['password_hash'].startswith('pbkdf2_sha256$'))


    def test_admin_user_management_api_crud(self):
        self.client.post(
            '/auth/login',
            data={'email': 'admin@autoshop.local', 'password': 'Admin123!', 'role': 'admin'},
            follow_redirects=False,
        )

        list_response = self.client.get('/api/admin/users')
        self.assertEqual(list_response.status_code, 200)
        list_payload = list_response.get_json()
        self.assertTrue(list_payload['success'])
        self.assertIn('users', list_payload)

        create_response = self.client.post(
            '/api/admin/users',
            json={
                'name': 'Created User',
                'email': 'created.user@autoshop.local',
                'password': 'Created123!',
                'role': 'frontdesk',
                'active': 1,
            },
        )
        self.assertEqual(create_response.status_code, 201)
        create_payload = create_response.get_json()
        self.assertTrue(create_payload['success'])
        user_id = create_payload['user_id']

        update_response = self.client.put(
            f'/api/admin/users/{user_id}',
            json={'name': 'Updated User', 'active': 0}
        )
        self.assertEqual(update_response.status_code, 200)
        self.assertTrue(update_response.get_json()['success'])


    def test_user_management_link_visible_for_admin_only(self):
        admin_client = scheduler_app.app.test_client()
        admin_client.post(
            '/auth/login',
            data={'email': 'admin@autoshop.local', 'password': 'Admin123!', 'role': 'admin'},
            follow_redirects=False,
        )
        admin_dashboard = admin_client.get('/admin/dashboard')
        self.assertEqual(admin_dashboard.status_code, 200)
        self.assertIn('href="/user-management"', admin_dashboard.get_data(as_text=True))

        frontdesk_client = scheduler_app.app.test_client()
        frontdesk_client.post(
            '/auth/login',
            data={'email': 'frontdesk@autoshop.local', 'password': 'Frontdesk123!', 'role': 'frontdesk'},
            follow_redirects=False,
        )
        frontdesk_dashboard = frontdesk_client.get('/admin/dashboard')
        self.assertEqual(frontdesk_dashboard.status_code, 200)
        self.assertNotIn('href="/user-management"', frontdesk_dashboard.get_data(as_text=True))

    def test_user_management_page_access_control(self):
        unauth_response = self.client.get('/user-management', follow_redirects=False)
        self.assertEqual(unauth_response.status_code, 302)
        self.assertTrue(unauth_response.headers['Location'].endswith('/login'))

        frontdesk_client = scheduler_app.app.test_client()
        frontdesk_client.post(
            '/auth/login',
            data={'email': 'frontdesk@autoshop.local', 'password': 'Frontdesk123!', 'role': 'frontdesk'},
            follow_redirects=False,
        )
        frontdesk_response = frontdesk_client.get('/user-management', follow_redirects=False)
        self.assertEqual(frontdesk_response.status_code, 302)
        self.assertTrue(frontdesk_response.headers['Location'].endswith('/admin/dashboard'))

        mechanic_client = scheduler_app.app.test_client()
        mechanic_client.post(
            '/auth/login',
            data={'email': 'mechanic@autoshop.local', 'password': 'Mechanic123!', 'role': 'mechanic'},
            follow_redirects=False,
        )
        mechanic_response = mechanic_client.get('/user-management', follow_redirects=False)
        self.assertEqual(mechanic_response.status_code, 302)
        self.assertTrue(mechanic_response.headers['Location'].endswith('/mechanic/dashboard'))

    def test_create_mechanic_requires_mapping(self):
        self.client.post(
            '/auth/login',
            data={'email': 'admin@autoshop.local', 'password': 'Admin123!', 'role': 'admin'},
            follow_redirects=False,
        )

        response = self.client.post(
            '/api/admin/users',
            json={
                'name': 'Unmapped Mechanic',
                'email': 'unmapped.mechanic@autoshop.local',
                'password': 'Created123!',
                'role': 'mechanic',
                'active': 1,
                'mechanic_id': '',
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()['error'], 'Mechanic mapping is required for mechanic role')

    def test_frontdesk_blocked_from_admin_user_management(self):
        self.client.post(
            '/auth/login',
            data={'email': 'frontdesk@autoshop.local', 'password': 'Frontdesk123!', 'role': 'frontdesk'},
            follow_redirects=False,
        )

        response = self.client.get('/api/admin/users')
        self.assertEqual(response.status_code, 403)

if __name__ == '__main__':
    unittest.main()
