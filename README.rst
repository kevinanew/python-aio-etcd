python-aio-etcd documentation
=============================

A python client for Etcd https://github.com/coreos/etcd

Official documentation: http://python-aio-etcd.readthedocs.org/

.. image:: https://travis-ci.org/M-o-a-T/python-aio-etcd.png?branch=master
   :target: https://travis-ci.org/M-o-a-T/python-aio-etcd

.. image:: https://coveralls.io/repos/M-o-a-T/python-aio-etcd/badge.svg?branch=master&service=github
   :target: https://coveralls.io/github/M-o-a-T/python-aio-etcd?branch=master

Installation
------------

Pre-requirements
~~~~~~~~~~~~~~~~

Install etcd (2.0.1 or later). This version of python-aio-etcd will only work correctly with the version 2.0.x or later.

This client is known to work with python 3.5. It will not work in older versions of python due to ist use of "async def" syntax.

Python 2 is not supported.

From source
~~~~~~~~~~~

.. code:: bash

    $ python setup.py install

Usage
-----

The basic methods of the client have changed compared to previous versions, to reflect the new API structure; however a compatibility layer has been maintained so that you don't necessarily need to rewrite all your existing code.

Create a client object
~~~~~~~~~~~~~~~~~~~~~~

.. code:: python

    import etcd

    client = etcd.Client() # this will create a client against etcd server running on localhost on port 4001
    client = etcd.Client(port=4002)
    client = etcd.Client(host='127.0.0.1', port=4003)
    client = etcd.Client(host='127.0.0.1', port=4003, allow_redirect=False)
    # wont let you run sensitive commands on non-leader machines, default is true

    # If you have defined a SRV record for _etcd._tcp.example.com pointing to the clients
    client = etcd.Client(srv_domain='example.com', protocol="https")

    # create a client against https://api.example.com:443/etcd
    client = etcd.Client(host='api.example.com', protocol='https', port=443, version_prefix='/etcd')

Write a key
~~~~~~~~~

.. code:: python

    await client.write('/nodes/n1', 1)
    # with ttl

    await client.set('/nodes/n1', 1)
    # Equivalent, for compatibility reasons.

    await client.write('/nodes/n2', 2, ttl=4)
    # sets the ttl to 4 seconds

Read a key
~~~~~~~~~

.. code:: python

    (await client.read('/nodes/n2')).value
    # read a value

    (await client.get('/nodes/n2')).value
    # Equivalent, for compatibility reasons.

    await client.read('/nodes', recursive = True)
    # get all the values of a directory, recursively.

Delete a key
~~~~~~~~~~~~

.. code:: python

    await client.delete('/nodes/n1')

Atomic Compare and Swap
~~~~~~~~~~~~

.. code:: python

    await client.write('/nodes/n2', 2, prevValue = 4)
    # will set /nodes/n2 's value to 2 only if its previous value was 4

    await client.write('/nodes/n2', 2, prevExist = False)
    # will set /nodes/n2 's value to 2 only if the key did not exist before

    await client.write('/nodes/n2', 2, prevIndex = 30)
    # will set /nodes/n2 's value to 2 only if the key was last modified at index 30

    await client.test_and_set('/nodes/n2', 2, 4)
    #equivalent to client.write('/nodes/n2', 2, prevValue = 4)

You can also atomically update a result:

.. code:: python

    await client.write('/foo','bar')
    result = await client.read('/foo')
    print(result.value) # bar
    result.value += u'bar'
    updated = await client.update(result)
    # if any other client wrote to '/foo' in the meantime this will fail

    print(updated.value) # barbar

Watch a key
~~~~~~~~~~~

.. code:: python

    result = await client.read('/nodes/n1')
    # start from a known initial value

    result = await client.read('/nodes/n1', wait = True, waitIndex = result.modifiedIndex+1)
    # will wait till the key is changed, and return once it's changed

    result = await client.read('/nodes/n1', wait = True, waitIndex = 10)
    # get all changes on this key starting from index 10

    result = await client.watch('/nodes/n1')
    # equivalent to client.read('/nodes/n1', wait = True)

    result = await client.watch('/nodes/n1', index = result.modifiedIndex+1)

If you want to time out the read() call, wrap it in `asyncio.wait_for`:

.. code:: python

    result = await asyncio.wait_for(client.read('/nodes/n1', wait=True), timeout=30)

Locking module
~~~~~~~~~~~~~~

.. code:: python

    # Initialize the lock object:
    # NOTE: this does not acquire a lock
    from aio_etcd.lock import Lock
    client = etcd.Client()
    lock = Lock(client, 'my_lock_name')

    # Use the lock object:
    await lock.acquire(blocking=True, lock_ttl=None)
    # will block until the lock is acquired
    # lock will live until we release it

    await lock.is_acquired()
    # returns True
    # NOTE: This tells you that _somebody_ has the lock
    await lock.acquire(lock_ttl=60)
    # renew a lock
    await lock.release() # release an existing lock
    await lock.is_acquired()  # False

    # The lock object may also be used as a context manager:
    async with Lock(client, 'customer1') as my_lock:
        do_stuff()
        await my_lock.is_acquired() # True
        await my_lock.acquire(lock_ttl = 60) # renew
    await my_lock.is_acquired() # probably False


Get machines in the cluster
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: python

    machines = await client.machines()

Get leader of the cluster
~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: python

    leaderinfo = await client.leader()

Generate a sequential key in a directory
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: python

    x = await client.write("/dir/name", "value", append=True)
    print("generated key: " + x.key)
    # actually the whole path
    print("stored value: " + x.value)

List contents of a directory
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: python

    #stick a couple values in the directory
    await client.write("/dir/name", "value1", append=True)
    await client.write("/dir/name", "value2", append=True)

    directory = await client.get("/dir/name")

    # loop through a directory's children
    for result in directory.children:
        print(result.key + ": " + result.value)

    # or just get the first child value
    print(directory.next(children).value)

Development setup
-----------------

The usual setuptools commands are available.

.. code:: bash

    $ python3 setup.py install

To test, you should have etcd available in your system path:

.. code:: bash

    $ python3 setup.py test

to generate documentation,

.. code:: bash

    $ cd docs
    $ make

Release HOWTO
-------------

To make a release

    1) Update release date/version in NEWS.txt and setup.py
    2) Run 'python setup.py sdist'
    3) Test the generated source distribution in dist/
    4) Upload to PyPI: 'python setup.py sdist register upload'

