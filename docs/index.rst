.. Jade documentation master file, created by
   sphinx-quickstart on Tue May 12 13:33:32 2020.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to Jade's RPC documentation!
========================================

.. toctree::
   :maxdepth: 2
   :caption: Contents:


get_version_info request
------------------------

.. code-block:: cbor

    {
        "method": "get_version_info",
        "id": "654503"
    }

.. _get_version_info_req-params:

get_version_info reply
----------------------

.. code-block:: cbor

    {
        "result": {
            "JADE_VERSION": "f11c4da",
            "JADE_OTA_MAX_CHUNK": 4096,
            "JADE_CONFIG": "BLE",
            "IDF_VERSION": "9778b16",
            "CHIP_FEATURES": "32000000",
            "EFUSEMAC": "246F288F6364",
            "JADE_FREE_HEAP": 1941624,
            "JADE_HAS_PIN": True
        },
        "id": "654503"
    }

.. _get_version_info_reply-params:


auth_user request
-----------------

.. code-block:: cbor

    {
        "id": "4",
        "method": "auth_user"
    }

.. _auth_user_req-params:

auth_user reply
---------------

.. code-block:: cbor

    {
        "id": "4",
        "result": True
    }

.. _auth_user_reply-params:

In this case the Jade is already logged in. Continue ahead with say OTA or sign transaction.
Otherwise if you get something like the below you will need to call the http end point (it's a post)


auth_user reply
---------------

.. code-block:: cbor

    {
        "id": "4",
        "result": {
            "url": "https://jadepin.blockstream.com/start_handshake"
            "onion": "http://mrrxtq6tjpbnbm7vh5jt6mpjctn7ggyfy5wegvbeff3x7jrznqawlmid.onion/start_handshake"
        }
    }

.. _auth_user_reply-params:

If indeed you need to authenticate the user as above you will need to forward the result of the start_handshake http post to
Jade using the message handshake_init.

The result of that will need then be posted to get_pin and the result of that send to jade using the message handshake_complete.
Then OTA and other functionality can proceed.

handshake_init request
----------------------

.. code-block:: cbor

    {
        "id": "5",
        "method": "handshake_init",
        "params": {
            "sig": "8c110cb45b31a98f9be3c5125f5df839449ce959da529e1e6ef7d9402126a88e1827452182ea016f6990aaf6de32f2faa2fa6a07b1cf0015cc3c1f8eb098b59c",
            "ske": "025b27c4ae5d0942370e66f20348b765fa910847325aa0d2b19bd12b2b090a83ba"
        }
    }

.. _handshake_init_req-params:

The result of that will be as follows:

handshake_init reply
--------------------

.. code-block:: cbor

    {
        "id": "5",
        "result": {
            "data": {
                "cke": "0223ef4a0214cb3ef79be0d04acd3122164d7663a571b85887ea8d44e004cda704",
                "encrypted_data": "22a4834e167792aa2d88ed311c397b0ffb4bc0eec06096b1c26375cf104fe4c94268fd0ed6ce30a9c5a7a2aaa501aca7e09d50477c694d0ec347c578c77352540cb87f3d6581161152c5291ef59a7923019b0b68420779ac989dc49759f4c7b037d55065cd4c72885b11b6b582c7db822973cc5f28cb6f74ed9a710573a8e5cb1969804d958769e1f52d887a18367f57eedaa81c08b25af7acc74a19cd97e59e",
                "hmac_encrypted_data": "77374b9c19ba8b34c2eb6cd97679fd8d8821b9dc7408f7d9d414c9f5a12ecb18",
                "ske": "025b27c4ae5d0942370e66f20348b765fa910847325aa0d2b19bd12b2b090a83ba"
            },
            "url": "https://jadepin.blockstream.com/get_pin"
            "onion": "http://mrrxtq6tjpbnbm7vh5jt6mpjctn7ggyfy5wegvbeff3x7jrznqawlmid.onion/get_pin"
        }
    }

.. _handshake_init_reply-params:

Again we should send the data to get_pin (or set_pin) and the result to handshake_complete

handshake_complete request
--------------------------

.. code-block:: cbor

    {
        "id": "6",
        "method": "handshake_complete",
        "params": {
            "encrypted_key": "33bbde37c3719114e80b380106ca265c2b95efebfd4e098068ba7ada601e24e499db74ed2b60b289aca949ed64912c65766fa26de87f6950a97ab184f006387e",
            "hmac": "c30348d55bee099d8738a4f4e4f80a18fd358e4843091a0a925e8af6a067f029"
        }
    }

.. _handshake_complete_req-params:

handshake_complete reply
------------------------

.. code-block:: cbor

    {
        "id": "6",
        "result": True
    }

.. _handshake_complete_reply-params:

ota request
-----------

.. code-block:: cbor

    {
        "id": "2",
        "method": "ota",
        "params": {
            "cmpsize": 579204,
            "fwsize": 926448,
            "otachunk": 4096
        }
    }

.. _ota_req-params:

ota reply
---------

.. code-block:: cbor

    {
        "id": "2",
        "result": True
    }

.. _ota_reply-params:

After this message you cand send ota_data messages.

Send all the compressed firmware to it and for each otachunk (please default to JADE_OTA_MAX_CHUNK) you will receive the usual cbor reply or cbor error.
You will then be able to send the ota_complete message to verify ota was successful (before the device reboots).

ota_complete_request
--------------------

.. code-block:: cbor

    {
        "id": "3",
        "method": "ota_complete"
    }

.. _ota_req-params:

ota_complete reply
------------------

.. code-block:: cbor

    {
        "id": "3",
        "result": True
    }

.. _ota_reply-params:



Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
