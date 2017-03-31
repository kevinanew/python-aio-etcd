Python-etcd documentation
=========================

An asynchronous python client for Etcd https://github.com/coreos/etcd




Installation
------------

Pre-requirements
................

Install etcd


From source
...........

.. code-block:: bash

    $ python setup.py install


Usage
-----

Create a client object
......................

.. code-block:: python

   import aio_etcd as etcd

   client = etcd.Client() # this will create a client against etcd server running on localhost on port 4001
   client = etcd.Client(port=4002)
   client = etcd.Client(host='127.0.0.1', port=4003)
   client = etcd.Client(host='127.0.0.1', port=4003, allow_redirect=False) # wont let you run sensitive commands on non-leader machines, default is true
   client = etcd.Client(
                host='127.0.0.1',
                port=4003,
                allow_reconnect=True,
                protocol='https',)

Set a key
.........

.. code-block:: python

    await client.write('/nodes/n1', 1)
    # with ttl
    await client.write('/nodes/n2', 2, ttl=4)  # sets the ttl to 4 seconds
    # create only
    await client.write('/nodes/n3', 'test', prevExist=False)
    # Compare and swap values atomically
    await client.write('/nodes/n3', 'test2', prevValue='test1') #this fails to write
    await client.write('/nodes/n3', 'test2', prevIndex=10) #this fails to write
    # mkdir
    await client.write('/nodes/queue', None, dir=True)
    # Append a value to a queue dir
    await client.write('/nodes/queue', 'test', append=True) #will write i.e. /nodes/queue/11
    await client.write('/nodes/queue', 'test2', append=True) #will write i.e. /nodes/queue/12

You can also atomically update a result:

.. code:: python

    result = await client.read('/foo')
    print(result.value) # bar
    result.value += u'bar'
    updated = await client.update(result) # if any other client wrote '/foo' in the meantime this will fail
    print(updated.value) # barbar



Get a key
.........

.. code-block:: python

    (await client.read('/nodes/n2')).value
    #recursively read a directory
    r = await client.read('/nodes', recursive=True, sorted=True)
    for child in r.children:
        print("%s: %s" % (child.key,child.value))

    await client.read('/nodes/n2', wait=True) #Waits for a change in value in the key before returning.
    await client.read('/nodes/n2', wait=True, waitIndex=10)

    # raises etcd.EtcdKeyNotFound when key not found
    try:
        client.read('/invalid/path')
    except etcd.EtcdKeyNotFound:
        # do something
        print "error"


Delete a key
............

.. code-block:: python

    await client.delete('/nodes/n1')
    await client.delete('/nodes', dir=True) #spits an error if dir is not empty
    await client.delete('/nodes', recursive=True) #this works recursively

Locking module
~~~~~~~~~~~~~~

.. code:: python

    # Initialize the lock object:
    # NOTE: this does not acquire a lock yet
    from aio_etcd.lock import Lock
    client = etcd.Client()
    lock = etcd.Lock(client, 'my_lock_name')

    # Use the lock object:
    await lock.acquire(blocking=True, # will block until the lock is acquired
          lock_ttl=None)  # lock will live until we release it
    lock.is_acquired  # True
    await lock.acquire(lock_ttl=60)  # renew a lock
    await lock.release()  # release an existing lock
    lock.is_acquired  # False

    # The lock object may also be used as a context manager:
    # (Python 3.5+)
    client = etcd.Client()
    async with etcd.Lock(client, 'customer1') as my_lock:
        do_stuff()
        my_lock.is_acquired  # True
        await my_lock.acquire(lock_ttl=60)
    my_lock.is_acquired  # False


Get machines in the cluster
...........................

.. code-block:: python

    machines = await client.machines()


Get leader of the cluster
.........................

.. code-block:: python

    leader_info = await client.leader()


Development setup
-----------------

To create a buildout,

.. code-block:: bash

  $ python bootstrap.py
  $ bin/buildout


to test you should have etcd available in your system path:

.. code-block:: bash

  $ bin/test

to generate documentation,

.. code-block:: bash

  $ cd docs
  $ make



Release HOWTO
-------------

To make a release,

  1) Update release date/version in NEWS.txt and setup.py
  2) Run 'python setup.py sdist'
  3) Test the generated source distribution in dist/
  4) Upload to PyPI: 'python setup.py sdist register upload'
  5) Increase version in setup.py (for next release)


List of contributors at https://github.com/jplana/python-etcd/graphs/contributors

Code documentation
------------------

.. toctree::
   :maxdepth: 2

   api.rst
