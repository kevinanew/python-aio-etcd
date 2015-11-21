import unittest
import shutil
import tempfile

import time

import aioetcd as etcd
import aioetcd.auth as auth
from .test_simple import EtcdIntegrationTest
from . import helpers


class TestAuthentication(unittest.TestCase):
    def setUp(self):
        # Restart etcd for each test (since some tests will lock others out)
        program = EtcdIntegrationTest._get_exe()
        self.directory = tempfile.mkdtemp(prefix='python-etcd')
        self.processHelper = helpers.EtcdProcessHelper(
            self.directory,
            proc_name=program,
            port_range_start=6001,
            internal_port_range_start=8001)
        self.processHelper.run(number=1)
        self.client = None

        # Wait for sync, to avoid:
        # "Not capable of accessing auth feature during rolling upgrades."
        time.sleep(0.5)

    def tearDown(self):
        if self.client is not None:
            self.client.close()
        self.processHelper.stop()
        shutil.rmtree(self.directory)

    @helpers.run_async
    def test_create_user(loop,self):
        self.client = auth.AuthClient(port=6001, loop=loop)
        user = yield from self.client.create_user('username', 'password')
        assert user.name == 'username'
        assert len(user.roles) == 0

    @helpers.run_async
    def test_create_user_with_role(loop,self):
        self.client = auth.AuthClient(port=6001, loop=loop)
        user = yield from self.client.create_user('username', 'password', roles=['root'])
        assert user.name == 'username'
        assert user.roles == ('root',)

    @helpers.run_async
    def test_create_user_add_role(loop,self):
        self.client = auth.AuthClient(port=6001, loop=loop)
        user = yield from self.client.create_user('username', 'password')
        yield from self.client.create_role('role')

        # Empty to [root]
        user.roles = ['root']
        user = yield from self.client.get_user('username')
        assert user.roles == ('root',)

        # [root] to [root,role]
        user.roles = ['root', 'role']
        user = yield from self.client.get_user('username')
        assert user.roles == ('role', 'root')

        # [root,role] to [role]
        user.roles = ['role']
        user = yield from self.client.get_user('username')
        assert user.roles == ('role',)

    def test_usernames_empty(self):
        self.client = auth.AuthClient(port=6001)
        assert len(self.client.usernames) == 0

    @helpers.run_async
    def test_usernames(loop,self):
        self.client = auth.AuthClient(port=6001, loop=loop)
        yield from self.client.create_user('username', 'password', roles=['root'])
        assert (yield from self.client.usernames) == ['username']

    @helpers.run_async
    def test_users(loop,self):
        self.client = auth.AuthClient(port=6001, loop=loop)
        yield from self.client.create_user('username', 'password', roles=['root'])
        users = yield from self.client.users()
        assert len(users) == 1
        assert users[0].name == 'username'

    @helpers.run_async
    def test_get_user(loop,self):
        self.client = auth.AuthClient(port=6001, loop=loop)
        yield from self.client.create_user('username', 'password', roles=['root'])
        user = yield from self.client.get_user('username')
        assert user.roles == ('root',)

    @helpers.run_async
    def test_get_user_not_found(loop,self):
        self.client = auth.AuthClient(port=6001, loop=loop)
        self.assertRaises(etcd.EtcdException, (yield from self.client.get_user), 'username')

    @helpers.run_async
    def test_set_user_password(loop,self):
        self.client = auth.AuthClient(port=6001, loop=loop)
        yield from self.client.create_user('username', 'password', roles=['root'])
        user = yield from self.client.get_user('username')
        assert not user.password
        user.password = 'new_password'
        assert not user.password

    @helpers.run_async
    def test_create_role(loop,self):
        self.client = auth.AuthClient(port=6001, loop=loop)
        role = yield from self.client.create_role('role')
        assert role.name == 'role'
        assert len(role.permissions) == 0

    @helpers.run_async
    def test_grant_role(loop,self):
        self.client = auth.AuthClient(port=6001, loop=loop)
        role = yield from self.client.create_role('role')

        # Read access to keys under /foo
        yield from role.permissions.set('/foo/*', 'R')
        assert len(role.permissions) == 1
        assert role.permissions['/foo/*'] == 'R'

        # Write access to the key at /foo/bar
        yield from role.permissions.set('/foo/bar', 'W')
        assert len(role.permissions) == 2

        # Full access to keys under /pub
        yield from role.permissions.set('/pub/*', 'RW')
        assert len(role.permissions) == 3

        # Fresh fetch to bust cache:
        role = yield from self.client.get_role('role')
        assert len(role.permissions) == 3

    @helpers.run_async
    def test_get_role(loop,self):
        self.client = auth.AuthClient(port=6001, loop=loop)
        role = yield from self.client.create_role('role')
        yield from role.permissions.set('/foo/*', 'R')

        role = yield from self.client.get_role('role')
        assert len(role.permissions) == 1

    @helpers.run_async
    def test_revoke_role(loop,self):
        self.client = auth.AuthClient(port=6001, loop=loop)
        role = yield from self.client.create_role('role')
        yield from role.permissions.set('/foo/*', 'R')

        yield from role.permissions.delete('/foo/*')

        role = yield from self.client.get_role('role')
        assert len(role.permissions) == 0

    @helpers.run_async
    def test_modify_role_invalid(loop,self):
        self.client = auth.AuthClient(port=6001, loop=loop)
        role = yield from self.client.create_role('role')
        self.assertRaises(ValueError, role.permissions.__setitem__, '/foo/*',
                          '')

    @helpers.run_async
    def test_modify_role_permissions(loop,self):
        self.client = auth.AuthClient(port=6001, loop=loop)
        role = yield from self.client.create_role('role')
        yield from role.permissions.set('/foo/*', 'R')

        # Replace R with W
        yield from role.permissions.set('/foo/*', 'W')
        assert role.permissions['/foo/*'] == 'W'
        role = yield from self.client.get_role('role')
        assert role.permissions['/foo/*'] == 'W'

        # Extend W to RW
        yield from role.permissions.set('/foo/*', 'WR')
        role = yield from self.client.get_role('role')
        assert role.permissions['/foo/*'] == 'RW'

        # NO-OP RW to RW
        yield from role.permissions.set('/foo/*', 'RW')
        role = yield from self.client.get_role('role')
        assert role.permissions['/foo/*'] == 'RW'

        # Reduce RW to W
        yield from role.permissions.set('/foo/*', 'W')
        role = yield from self.client.get_role('role')
        assert role.permissions['/foo/*'] == 'W'

    @helpers.run_async
    def test_role_names_empty(self):
        self.client = auth.AuthClient(port=6001, loop=loop)
        assert (yield from self.client.role_names()) == ['root']

    @helpers.run_async
    def test_role_names(loop,self):
        self.client = auth.AuthClient(port=6001, loop=loop)
        yield from self.client.create_role('role')
        assert (yield from self.client.role_names()) == ['role', 'root']

    @helpers.run_async
    def test_roles(loop,self):
        self.client = auth.AuthClient(port=6001, loop=loop)
        yield from self.client.create_role('role')
        assert len((yield from self.client.roles())) == 2

    @helpers.run_async
    def test_enable_auth(loop,self):
        self.client = auth.AuthClient(port=6001, loop=loop)
        # Store a value, lock out guests
        yield from self.client.write('/foo', 'bar')
        yield from self.client.create_user('root', 'rootpassword')
        # Creating role before auth is enabled prevents default permissions
        yield from self.client.create_role('guest')
        yield from self.client.toggle_auth(True)

        # Now we can't access key:
        try:
            yield from self.client.get('/foo')
            self.fail('Expected exception')
        except etcd.EtcdException as e:
            assert 'Insufficient credentials' in str(e)

        # But an authenticated client can:
        root_client = etcd.Client(port=6001,
                                  username='root',
                                  password='rootpassword', loop=loop)
        assert (yield from root_client.get('/foo')).value == 'bar'

    @helpers.run_async
    def test_enable_auth_before_root_created(loop,self):
        self.client = auth.AuthClient(port=6001, loop=loop)
        self.assertRaises(etcd.EtcdException, (yield from self.client.toggle_auth), True)

