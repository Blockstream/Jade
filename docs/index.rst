.. Jade documentation master file, created by
   sphinx-quickstart on Tue May 12 13:33:32 2020.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to Jade's RPC documentation!
====================================

.. toctree::
   :maxdepth: 2
   :caption: Contents:

* All Jade RPC messages are CBOR, roughly based on the format of json-rpc messges.
* The order of named fields inside the messages is unimportant.  The order of items in array elements usually is important.
* In most cases the flow is message-reply-message-reply... the exception is the legacy sign-tx flow where n messages are sent before n replies are recieved.
* In some cases there may be a delay between sending a message and a reply being sent, where some physical interaction with the Jade unit is required.
* In general, the types used are string, boolean, uint32/64, and raw byte-strings for binary data.
* Every message contains an `id` field - an arbitrary string up to 16 characters - which is included in the reply.
* Several calls require a `network` parameter.  Allowed values are: 'mainnet' and 'liquid'. If using a test wallet, 'testnet', 'testnet-liquid', 'localtest' and 'localtest-liquid' are allowed.
* Successful action replies include a `result` structure, specific to each method.
* Failed/errored/declined actions instead include a common `error` structure.
  
.. _common_error_reply:

common error reply
------------------

.. code-block:: cbor

    {
        "id": "5",
        "error": {
            "code": -32603,
            "message": "There was an error with your request"
            "data": <bytes>
        }
    }

* 'code' values are listed in `main/utils/cbor_rpc.h`.
* 'message' should be a meaningful string describing the error encountered.
* 'data' content is optional, and usually unused/null.
  
.. _get_extended_data_request:

get_extended_data request
-------------------------

.. code-block:: cbor

    {
        "id": "11",
        "method": "get_extended_data"
        "params": {
            "origid": "1234",
            "orig": "sign_psbt",
            "seqnum": 3,
            "seqlen": 6
        }
    }

* 'get_extended_data' is to be used where a prior reply has included 'seqnum' and 'seqlen' fields which indicate incomplete data
* 'origid' should be the id of the original request message and initial reply
* 'orig' should be the 'method' of the original request message
* 'seqlen' should be the 'seqlen' in the replies - indicating the total number of message replies which will be required
* 'seqnum' should indicate the next fragment required - it should always be less-than or equal-to the 'seqlen'
* NOTE: atm 'seqnum' *MUST* indicate the next fragement.  ie. ie must be the last received seqnum + 1.
* NOTE: at the moment these messages are only used for 'sign_psbt' replies, where the full psbt binary may be sufficiently large that it needs to be split over multiple messages.  See sign_psbt_request_.
* Use of these messages may increase in future firmware releases.

.. _get_extended_data_reply:

get_extended_data reply
-----------------------

.. code-block:: cbor

    {
        "id": "11",
        "result": {
            <as appropriate for parent message>
        }
    }

* The content of the message will be dependent on the original message whose reply data is being split over multiple messages.

.. _ping_request:

ping request
------------

Used to test the connection to Jade and that Jade is powered on and receiving data, which returns whether the main task is currently handling a client message, handling user ui menu navigation, or is idle.

NOTE: unlike all other calls this is not queued and handled in fifo order - this message is handled immediately and the response sent as quickly as possible.
This call does not block.
If this call is made in parallel with Jade processing other messages, the replies may be out of order (although the message 'id' should still be correct).
Use with caution.

.. code-block:: cbor

    {
        "id": "2712",
        "method": "ping"
    }

.. _ping_reply:

ping reply
----------

.. code-block:: cbor

    {
        "id": "2712",
        "result": 0
    }

* The result is 0 if the main jade task is idle, 1 if handling a client message, or 2 if handling ui menu navigation.
* If used with a short timeout this message is ideal for detecting whether Jade is powered/active.

.. _get_version_info_request:

get_version_info request
------------------------

Used to obtain summary fields describing this Jade hw unit.

.. code-block:: cbor

    {
        "id": "90210",
        "method": "get_version_info"
    }

.. _get_version_info_reply:

get_version_info reply
----------------------

.. code-block:: cbor

    {
        "id": "90210",
        "result": {
            "JADE_VERSION": "0.1.32",
            "JADE_OTA_MAX_CHUNK": 4096,
            "JADE_CONFIG": "BLE",
            "BOARD_TYPE": "JADE",
            "JADE_FEATURES": "SB",
            "IDF_VERSION": "v4.3.1",
            "CHIP_FEATURES": "32000000",
            "EFUSEMAC": "246F288F6364",
            "BATTERY_STATUS": 5,
            "JADE_STATE": "LOCKED",
            "JADE_NETWORKS': "MAIN",
            "JADE_HAS_PIN": true
        }
    }

* 'BATTERY_STATUS' : positive integer value up to 5 (fully charged).

* 'JADE_STATE' :
  
  - 'UNINIT' - no wallet set on the hw, mnemonic not entered, unit uninitialised.
  - 'UNSAVED' - wallet mnemonic has been set on hw, but not yet persisted with blind pinserver.
  - 'LOCKED' - wallet set, but currently locked - requires PIN entry to unlock.
  - 'READY' - wallet set and unlocked for this interface, ready to use.
  - 'TEMP' - hw currently set with a temporary ('Emergency Restore') wallet, ready to use.
    
* 'JADE_NETWORKS' :
  
  - 'MAIN' - wallet is locked to mainnet/production networks and cannot be used on testnet or regtest networks.
  - 'TEST' - wallet is locked to testnet/regtest/localtest networks, and cannot be used on mainnet or liquid production networks.
  - 'ALL' - wallet is not (yet) locked to a specific network type.

.. _update_pinserver_request:

update_pinserver request
------------------------

Call to update the details of the blind pinserver used to authenticate Jade unlock attempts.

.. code-block:: cbor

    {
        "id": "101",
        "method": "update_pinserver"
        "params": {
            "reset_details": true,
            "reset_certificate": true,
            "urlA": "https://test.pinserver.com",
            "urlB": "http://pinserveronion.com",
            "pubkey": <33 bytes>,
            "certificate": "<certificate pem string>"
        }
    }

* All fields are optional (although an empty message has no effect).
* 'reset_details' - resets to default pinserver (ie. *https://jadepin.blockstream.com*)
* 'reset_certificate' - resets any additional certificate (to none)
* 'urlA'/'urlB' - sets up to two urls for the pinserver.  (Setting only urlA will set urlB to none).
* 'pubkey' - 33-byte EC public key of pinserver.

- Note: Jade applies some validation to parameter combinations, for example it is not possible to set only 'urlB', to set 'pubkey' without at least 'urlA', to both 'set' and 'reset' fields, etc.

.. _update_pinserver_reply:

update_pinserver reply
----------------------

.. code-block:: cbor

    {
        "id": "101",
        "result": true
    }

.. _set_epoch_request:

set_epoch request
-----------------

Jade has an internal clock/oscillator, but no absolute time is retained over power-cycles.
This call allows setting the current epoch time, to initialise the internal clock.
NOTE: this is required to use the TOTP authentication feature.

.. code-block:: cbor

    {
        "id": "926",
        "method": "set_epoch"
        "params": {
            "epoch": 1654086434
        }
    }

* 'epoch' - unix epoch time, in seconds.

.. _set_epoch_reply:

set_epoch reply
---------------

.. code-block:: cbor

    {
        "id": "926",
        "result": true
    }

.. _add_entropy_request:

add_entropy request
-------------------

Jade has an internal entropy pool generated by sampling several of the environmental sensors,
but this call allows the client to contribute to that entropy pool by passing in additional
entropy bytes.

.. code-block:: cbor

    {
        "id": "925",
        "method": "add_entropy"
        "params": {
            "entropy": <bytes>
        }
    }

* 'entropy' - a byte sequence of any length is accepted, and added into the entropy pool.

.. _add_entropy_reply:

add_entropy reply
-----------------

.. code-block:: cbor

    {
        "id": "925",
        "result": true
    }

.. _logout_request:

logout request
--------------

Logout of any wallet loaded on Jade.  Key material is freed and zero'd.
Jade is returned to a 'locked' state, with no keys/wallet loaded.

.. code-block:: cbor

    {
        "id": "14159",
        "method": "logout"
    }

.. _logout_reply:

logout reply
------------

.. code-block:: cbor

    {
        "id": "14159",
        "result": true
    }

.. _auth_user_request:

auth_user request
-----------------

A call to 'auth_user' is required to unlock a Jade wallet and also to complete wallet initialisation.

.. code-block:: cbor

    {
        "id": "6",
        "method": "auth_user",
        "params": {
            "network": "mainnet"
            "epoch": 1654086434
        }
    }

* If completing initialisation, the call will result in the user setting a PIN (on the device) to persist the wallet with the blind pinserver. The wallet is locked to the type of network passed (ie. locked for use on mainnet and liquid production networks, OR for use on testnet/liquid-testnet/regtest networks).
* If unlocking an initialised unit, the network passed indicates the intended network to use - an error is returned if this is inconsistent with that set when the wallet was initialised/persisted. The user will be asked to enter the PIN on the device, and the blind pinserver will be used to unlock the wallet.
* 'epoch' is optional, and if passed sets the value of the internal clock - see set_epoch_request_ above.
* Calling 'auth_user' on a wallet that is already unlocked validates the passed network and sets any epoch value, and returns immediately without requiring user interation.

.. _auth_user_reply:

auth_user reply
---------------

.. code-block:: cbor

    {
        "id": "6",
        "result": true
    }

In this case the Jade is already/successfully logged in and the passed network is consistent with the wallet.
Continue ahead with OTA, get-xpub, get-address or signing messages and transactions.

Otherwise if a message like the below is received, the given http end point must be called (POST) to authenticate the user, passing the 'data' payload to the remote blind pinserver, and passing the reply into the Jade method given.

NOTE: in this instance some of 'byte' data fields may actually be hexidecimal strings - this data is opaque to the client and should simply be passed between Jade and the blind pinserver.

.. code-block:: cbor

    {
        "id": "6",
        "result": {
            "http_request": {
                "params": {
                    "urls": [
                        "https://jadepin.blockstream.com/start_handshake",
                        "http://mrrxtq6tjpbnbm7vh5jt6mpjctn7ggyfy5wegvbeff3x7jrznqawlmid.onion/start_handshake"
                    ],
                    "method": "POST",
                    "accept": "json",
                    "data": ""
                }
                "on-reply": "handshake_init"
            }
        }
    }

The first step is to initiate a secure channel with the pinserver.  Either URL can be used to get a key from the pinserver.
The response body should be json, which should be re-encoded as cbor and passed to Jade as the 'params' to the 'handshake_init' method.
It should look similar to the below:

.. _handshake_init_request:

handshake_init request
----------------------

.. code-block:: cbor

    {
        "id": "R2D2",
        "method": "handshake_init",
        "params": {
            "sig": "8c110cb45b31a98f9be3c5125f5df839449ce959da529e1e6ef7d9402126a88e1827452182ea016f6990aaf6de32f2faa2fa6a07b1cf0015cc3c1f8eb098b59c",
            "ske": "025b27c4ae5d0942370e66f20348b765fa910847325aa0d2b19bd12b2b090a83ba"
        }
    }

The result of 'handshake_init' provides the http-call to make next with the data (derived from the entered PIN) to pass.

.. _handshake_init_reply:

handshake_init reply
--------------------

.. code-block:: cbor

    {
        "id": "R2D2",
        "result": {
            "http_request": {
                "params": {
                    "urls": [
                        "url": "https://jadepin.blockstream.com/get_pin",
                        "onion": "http://mrrxtq6tjpbnbm7vh5jt6mpjctn7ggyfy5wegvbeff3x7jrznqawlmid.onion/get_pin"
                    ],
                    "method": "POST",
                    "accept": "json",
                    "data": {
                        "cke": "0223ef4a0214cb3ef79be0d04acd3122164d7663a571b85887ea8d44e004cda704",
                        "encrypted_data": "22a4834e167792aa2d88ed311c397b0ffb4bc0eec06096b1c26375cf104fe4c94268fd0ed6ce30a9c5a7a2aaa501aca7e09d50477c694d0ec347c578c77352540cb87f3d6581161152c5291ef59a7923019b0b68420779ac989dc49759f4c7b037d55065cd4c72885b11b6b582c7db822973cc5f28cb6f74ed9a710573a8e5cb1969804d958769e1f52d887a18367f57eedaa81c08b25af7acc74a19cd97e59e",
                        "hmac_encrypted_data": "77374b9c19ba8b34c2eb6cd97679fd8d8821b9dc7408f7d9d414c9f5a12ecb18",
                        "ske": "025b27c4ae5d0942370e66f20348b765fa910847325aa0d2b19bd12b2b090a83ba"
                    }
                }
                "on-reply": "handshake_complete"
            }
        }
    }

Again the 'data' should be sent (as json) to the url provided (either is fine), and the response body forwarded to the 'handshake_complete' Jade method.
The request should look like the below:

.. _handshake_complete_request:

handshake_complete request
--------------------------

.. code-block:: cbor

    {
        "id": "C3PO",
        "method": "handshake_complete",
        "params": {
            "encrypted_key": "33bbde37c3719114e80b380106ca265c2b95efebfd4e098068ba7ada601e24e499db74ed2b60b289aca949ed64912c65766fa26de87f6950a97ab184f006387e",
            "hmac": "c30348d55bee099d8738a4f4e4f80a18fd358e4843091a0a925e8af6a067f029"
        }
    }

.. _handshake_complete_reply:

handshake_complete reply
------------------------

.. code-block:: cbor

    {
        "id": "C3PO",
        "result": true
    }

* A result of 'true' means the PIN was correct and the Jade wallet is now unlocked and ready to use.
* A result of 'false' here would imply the entered PIN was incorrect, authentication failed, and so the wallet is still locked.

.. _ota_request:

ota request
-----------

Request to initiate a firmware update passing the full firmware image.

.. code-block:: cbor

    {
        "id": "13",
        "method": "ota",
        "params": {
            "fwsize": 926448,
            "cmpsize": 579204,
            "cmphash": <32 bytes>,
            "fwhash": <32 bytes>
        }
    }

* 'fwsize' is the total length of the final firmware when uncompressed.
* 'cmpsize' is the length of the compressed firmware image which will be uploaded.
* 'cmphash' is the sha256 hash of the compressed firmware image.
* 'fwhash' is the sha256 hash of the final firmware image to be booted.
* NOTE: 'fwhash' is a new addition and is optional at this time, although it will become mandatory in a future release.

.. _ota_reply:

ota reply
---------

.. code-block:: cbor

    {
        "id": "13",
        "result": true
    }

After this reply is received, the compressed firmware is sent in chunks using 'ota_data' messages.  The chunks can be any size up to the `JADE_OTA_MAX_CHUNK` limit (see get_version_info_request_).

.. _ota_delta_request:

ota_delta request
-----------------

Request to initiate a firmware update using a binary diff/patch to be applied onto the current running firmware.

.. code-block:: cbor

    {
        "id": "7",
        "method": "ota",
        "params": {
            "fwsize": 926448,
            "patchsize": 987291,
            "cmpsize": 14006,
            "cmphash": <32 bytes>
        }
    }

* 'fwsize' is the total length of the final firmware when uncompressed.
* 'patchsize' is the length of the patch when uncompressed.
* 'cmpsize' is the length of the compressed firmware patch which will be uploaded.
* 'cmphash' is the sha256 hash of the compressed firmware patch.

.. _ota_delta_reply:

ota delta reply
---------------

See ota_reply_

.. _ota_data_request:

ota_data request
----------------

.. code-block:: cbor

    {
        "id": "48",
        "method": "ota_data",
        "params": <bytes>
    }

.. _ota_data_reply:

ota_data reply
--------------

.. code-block:: cbor

    {
        "id": "48",
        "result": true
    }

We then send the 'ota_complete' message to verify the OTA was successful (before the device reboots).

.. _ota_complete_request:

ota_complete request
--------------------

.. code-block:: cbor

    {
        "id": "50",
        "method": "ota_complete"
    }

.. _ota_complete_reply:

ota_complete reply
------------------

.. code-block:: cbor

    {
        "id": "50",
        "result": true
    }

* A 'true' response implies the firmware upload completed successfully, and the next restart will attempt to boot the new firmware.

.. _register_descriptor_request:

register_descriptor request
---------------------------

Jade can store up to 16 user-defined miniscript descriptor wallet configurations, which need to be confirmed on the hw.

.. code-block:: cbor

    {
        "id": "186282",
        "method": "register_descriptor"
        "params": {
            "network": "mainnet",
            "descriptor_name": "inheritance",
            "descriptor": "wsh(or_d(pk(@0/<0;1>/*),and_v(v:multi(2,@1/<0;1>/*,@2/<0;1>/*),older(4320))))",
            "datavalues": [
                {
                    "key": "@0",
                    "value": "[1bf12fe0/48'/1'/0'/2']tpubDEHXLZfMAAM5duEnX6SSnZjGYbrxqXvRJmMxw8MFwr3gu4LC4DSxR9KVEfVDVcZxre4XL5tGcwVRrHwQ9euTMnSq6P6BqREemaqrFsC96Fy",
                },
                {
                    "key": "@1",
                    "value": "[eda3d606/48'/1'/0'/2']tpubDEAmqvQkhqP6SbfbSPu3AeRR9kfHLFXYvNDiWashLy7V2zicg1YLg654AqfomsC6kFwTs4MpcnqwxN2AnYAqi5JZeuVDBn3rfZZLTaAuS8Y",
                },
                {
                    "key": "@2",
                    "value": "[e1640396/48'/1'/0'/2']tpubDFgDvZifofePphQiVjLfkov8YTDg3UPuHRvt6LzbySYMZQhN19p6zvR7NTEXi1ZJAMNostHMTnz2sfXXYcJFQqtyCnNuUfgYqsahxTLGJq2",
                }
            ]
        }
    }

* 'descriptor_name' is a string, and must be less than 16 characters long.  Using an existing name will overwrite the corresponding descriptor registration record.
* 'descriptor' is the descriptor string.  It must be a 'wallet policy' miniscript expression with the keys presented in the accompanying datavalues map.
* 'datavalues' is the map of signers' keys, which must include an entry for the Jade signer.

.. _register_descriptor_reply:

register_descriptor reply
-------------------------

.. code-block:: cbor

    {
        "id": "186282",
        "result": true
    }

.. _register_multisig_request:

register_multisig request
-------------------------

Jade can store up to 16 user-defined multisig wallet configurations, which need to be confirmed on the hw.

.. code-block:: cbor

    {
        "id": "6000000$",
        "method": "register_multisig"
        "params": {
            "network": "mainnet",
            "multisig_name": "small_beans",
            "descriptor": {
                "variant": "sh(multi(k))",
                "sorted": true,
                "threshold": 2,
                "master_blinding_key": <32-bytes>
                "signers": [
                    {
                        "fingerprint": <4 bytes>,
                        "derivation": [44, 2147483648, 2147483648],
                        "xpub": "tpubDDCNstnPhbdd4vwbw5UWK3vRQSF1WXQkvBHpNXpKJAkwFYjwu735EH3GVf53qwbWimzewDUv68MUmRDgYtQ1AU8FRCPkazfuaBp7LaEaohG",
                        "path": [3, 1]
                    },
                    {
                        "fingerprint": <4 bytes>,
                        "derivation": [2147483651, 2147483649, 1],
                        "xpub": "tpubDDExQpZg2tziZ7ACSBCYsY3rYxAZtTRBgWwioRLYqgNBguH6rMHN1D8epTxUQUB5kM5nxkEtr2SNic6PJLPubcGMR6S2fmDZTzL9dHpU7ka",
                        "path": [1]
                    }
                ]
            }
        }
    }

or:

.. code-block:: cbor

    {
        "id": "6000000$",
        "method": "register_multisig"
        "params": {
            "multisig_file": "Name: MainWallet\nPolicy: 2 of 3\nFormat: P2WSH\nDerivation: m/48'/0'/0'/2\n\nB237FE9D: xpub6E8C7BX4c7qfTsX7urnXggcAyFuhDmYLQhwRwZGLD9maUGWPinuc9k96ejhEQ1DCk..."
        }
    }

* 'multisig_name' is a string, and must be less than 16 characters long.  Using an existing name will overwrite the corresponding multisig registration record.
* 'variant' indicates the script type used, and must be one of: 'sh(multi(k))', 'wsh(multi(k))' or 'sh(wsh(multi(k)))'
* 'master_blinding_key' should be set for multisigs to be used on a Liquid network if the Jade is to provide confidential addresses, blinding keys, blinding nonces, asset blinding factors or output commitments.  Otherwise it can be omitted.
* 'fingerprint' is the 4-byte wallet origin fingerprint - at least one signer must reference the Jade signer's root xpub fingerprint.
* 'derivation' is the path from the origin to the given xpub - currently it is only used for the Jade signer, where it is used to verify the passed xpub.
* 'xpub' is the signer xpub, as described by the 'fingerprint' and 'derivation' (validated, in the case of this unit's signer).
* 'path' is a path applied to the xpub, to yield the root signer for this multisig.  In most cases this is empty '[]'.
* Alternatively, the contents of the multisig wallet file as produced by several wallet apps (BluwWallet, Sparrow, Nunchuk etc.) can be passed.


.. _register_multisig_reply:

register_multisig reply
-----------------------

.. code-block:: cbor

    {
        "id": "6000000$",
        "result": true
    }

.. _get_registered_multisigs_request:

get_registered_multisigs request
--------------------------------

Call to fetch brief summary of any registered multisig wallets associated with the hw signer.

.. code-block:: cbor

    {
        "id": "42",
        "method": "get_registered_multisigs"
    }

.. _get_registered_multisigs_reply:

get_registered_multisigs reply
------------------------------

.. code-block:: cbor

    {
        "id": "42",
        "result": {
            "work-team": {
                "variant": "wsh(multi(k))",
                "sorted": true,
                "threshold": 2,
                "num_signers": 3,
                "master_blinding_key": <32-bytes>
            },
            "family": {
                "variant": "sh(wsh(multi(k)))",
                "sorted": false,
                "threshold": 2,
                "num_signers": 3,
                "master_blinding_key": null
            },
            "small_beans": {
                "variant": "sh(multi(k))",
                "sorted": true,
                "threshold": 2,
                "num_signers": 2,
                "master_blinding_key": <32-bytes>
            },
        }
    }

.. _get_registered_multisigs_request:

get_registered_multisig request
-------------------------------

Call to fetch signer details of any registered multisig wallets associated with the hw signer.
NOTE: the multisig wallet must have been registered with firmware v1.0.23 or later for the full signer details to be persisted and available.

.. code-block:: cbor

    {
        "id": "43",
        "method": "get_registered_multisig"
        "params": {
            "multisig_name": "busacct",
            "as_file": false
        }
    }

* If 'as_file' is true, the flat-file format as supported by several wallet apps is returned in a single string
* If 'as_file' is false, structured json is returned


.. _get_registered_multisigs_reply:

get_registered_multisig reply
-----------------------------

.. code-block:: cbor

    {
        "id": "43",
        "multisig_name": "busacct",
        "multisig_file": "Name: MainWallet\nPolicy: 2 of 3\nFormat: P2WSH\nDerivation: m/48'/0'/0'/2\n\nB237FE9D: xpub6E8C7BX4c7qfTsX7urnXggcAyFuhDmYLQhwRwZGLD9maUGWPinuc9k96ejhEQ1DCk..."
    }

or:

.. code-block:: cbor

    {
        "id": "43",
        "multisig_name": "busacct",
        "descriptor": {
            "variant": "wsh(multi(k))",
            "sorted": true,
            "threshold": 2,
            "master_blinding_key": <32-bytes>,
            "signers": [
                {
                    "fingerprint": <4 bytes>,
                    "derivation": [44, 2147483648, 2147483648],
                    "xpub": "tpubDDCNstnPhbdd4vwbw5UWK3vRQSF1WXQkvBHpNXpKJAkwFYjwu735EH3GVf53qwbWimzewDUv68MUmRDgYtQ1AU8FRCPkazfuaBp7LaEaohG",
                    "path": [3, 1]
                },
                {
                    "fingerprint": <4 bytes>,
                    "derivation": [2147483651, 2147483649, 1],
                    "xpub": "tpubDDExQpZg2tziZ7ACSBCYsY3rYxAZtTRBgWwioRLYqgNBguH6rMHN1D8epTxUQUB5kM5nxkEtr2SNic6PJLPubcGMR6S2fmDZTzL9dHpU7ka",
                    "path": [1]
                }
            ]
        }
    }

.. _register_otp_request:

register_otp request
--------------------

Request to register an OTP secret and its associated parameters, for subsequent fetching of OTP codes.

.. code-block:: cbor

    {
        "id": "405",
        "method": "register_otp",
        "params": {
            "name": "test_otp",
            "uri": "otpauth://totp/Green:jade@blockstream.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=GreenWallet&digits=8&algorithm=SHA256"
        }
    }

.. _register_otp_reply:

register_otp reply
------------------

.. code-block:: cbor

    {
        "id": "405",
        "result": true
    }

.. _get_otp_code:

get_otp_code request
--------------------

Request to geta new OTP code for a previously registered OTP record.

.. code-block:: cbor

    {
        "id": "406",
        "method": "get_otp_code",
        "params": {
            "name": "test_otp"
        }
    }

.. _get_otp_code_reply:

get_otp_code reply
------------------

.. code-block:: cbor

    {
        "id": "406",
        "result": 74935634
    }

.. _get_xpub_request:

get_xpub request
----------------

Request to fetch an xpub for the given bip32 path, expressed as an array of (uint64) integers.

.. code-block:: cbor

    {
        "id": "404",
        "method": "get_xpub",
        "params": {
            "network": "mainnet",
            "path": [2147483697, 2147483648, 2147483648, 0, 143]
        }
    }

.. _get_xpub_reply:

get_xpub reply
--------------

.. code-block:: cbor

    {
        "id": "404",
        "result": "xpub661MyMwAqRbcGJMgtWQnZ6b8Nk1YE4RkR2sAT9ZE3ovUH95wH5UxY1qkg7aRC7MdQD7YMauTncJMMHyWdDmkCeKMMoVwzJoK5DbZHHhinUQ"
    }

.. _get_receive_address_request:

get_receive_address request
---------------------------

Request to fetch a Blockstream Green (multisig shield) address.

.. code-block:: cbor

    {
        "id": "T-1000",
        "method": "get_receive_address",
        "params": {
            "network": "mainnet",
            "subaccount": 2,
            "branch": 1,
            "pointer": 114,
            "recovery_xpub": None,
            "csv_blocks": 65535
        }
    }

* 'recovery_xpub' (normal string xpub) is used if the subaccount indicated is a '2of3' account (in which case 'csv_blocks' should be omitted).
* 'recovery_xpub' should be omitted if the subaccount type is not '2of3'.
* 'csv_blocks' should be omitted if the subaccount is not csv-enabled.

or:

Request to fetch a single-sig address for the given script type and bip32 path, expressed as an array of (uint64) integers.

.. code-block:: cbor

    {
        "id": "T-1000",
        "method": "get_receive_address",
        "params": {
            "network": "mainnet",
            "variant": "sh(wpkh(k))",
            "path": [2147483697, 2147483648, 2147483648, 0, 143]
        }
    }

* 'variant' indicates the script type used, and must be one of: 'pkh(k)', 'wpkh(k)' or 'sh(wpkh(k))'

or:

Request to fetch a multisig-sig address for the given (previously registered) multisig record, and bip32 path suffixes.

.. code-block:: cbor

    {
        "id": "T-1000",
        "method": "get_receive_address",
        "params": {
            "network": "mainnet",
            "multisig_name": "small_beans",
            "paths": [
                [0, 43],
                [0, 14]
            ]
        }
    }

* 'multisig_name' identifies a multisig wallet previously registered on the Jade hw unit.
* 'paths' are the path suffixes to be applied to the xpubs in the multisig, in the order in which they were in the original registration.  NOTE: usually these paths will all be identical.


- NOTE: Addresses generated for the liquid networks are 'confidential addresses' by default.  In order to confirm a 'non-confidential address' on liquid, pass an additional boolean flag '"confidential": false' in 'params'.

.. _get_receive_address_reply:

get_receive_address reply
-------------------------

* NOTE: The reply is not sent until the user has explicitly confirmed the address on the hw.

.. code-block:: cbor

    {
        "id": "T-1000",
        "result": "3A9HgJqKS5FZtGykWKuVBKyosFppojPPj5"
    }

.. _get_identity_pubkey_request:

get_identity_pubkey request
---------------------------

Request to fetch a pubkey for a given identity and index (see SLIP-0013).

NOTE: currently this call only supports 'ssh://' and 'gpg://' using nist256p1 (secp256r1)

.. code-block:: cbor

    {
        "id": "31415916",
        "method": "get_identity_pubkey",
        "params": {
            "identity": "ssh://jade@blockstream.com",
            "curve": "nist256p1",
            "index": 12,
            "type": "slip-0013"
        }
    }

* 'identity' should be an ssh:// or gpg:// uri
* 'curve' must be 'nist256p1'.
* 'index' is optional, and defaults to zero.
* 'index' can be supplied, to generate multiple keys for the same identity string.
* 'type' is a string which defines how the key will be derived, and must be 'slip-0013' for an identity pubkey, or 'slip-0017' for an ecdh pubkey.


.. _get_identity_pubkey_reply:

get_identity_pubkey reply
-------------------------

.. code-block:: cbor

    {
        "id": "31415916",
        "result": <65 bytes>
    }

* 'result' is an uncompressed EC public key point
* If 'type' is 'slip-0013', the returned key should be consistent with sign_identity_reply_ below.
* If 'type' is 'slip-0017', the returned key should be consistent with get_identity_shared_key_reply_ below.

.. _get_identity_shared_key_request:

get_identity_shared_key request
-------------------------------

Request to fetch a shared secret for an identity and a counterparty public key (see SLIP-0017).

NOTE: currently this call only supports 'ssh://' and 'gpg://' using nist256p1 (secp256r1)

.. code-block:: cbor

    {
        "id": "52",
        "method": "get_identity_shared_key",
        "params": {
            "identity": "gpg://Jade <jade@blockstream.com>",
            "curve": "nist256p1",
            "their_pubkey": <65 bytes>
            "index": 13
        }
    }

* 'identity' should be an ssh:// or gpg:// uri
* 'curve' must be 'nist256p1'.
* 'their_pubkey' is an uncompressed EC public key point
* 'index' is optional, and defaults to zero.
* 'index' can be supplied, to generate multiple keys for the same identity string.

.. _get_identity_shared_key_reply:

get_identity_shared_key reply
-----------------------------

.. code-block:: cbor

    {
        "id": "52",
        "result": <32 bytes>
    }

* 'result' is an ecdh shared secret for the passed identity and counterparty public key
* This should be consistent with get_identity_pubkey_reply_ (with a 'type' of 'slip-0017') above.

.. _sign_identity_request:

sign_identity request
---------------------

Request to sign to confirm identity, using RFC6979 (see SLIP-0013).

NOTE: currently this call only supports 'ssh://' and 'gpg://' using nist256p1 (secp256r1)

.. code-block:: cbor

    {
        "id": "50wtlyl",
        "method": "sign_identity",
        "params": {
            "identity": "ssh://jade@blockstream.com",
            "curve": "nist256p1",
            "challenge": <bytes>
            "index": 0
        }
    }

* 'identity' should be an ssh:// or gpg:// uri
* 'curve' must be 'nist256p1'.
* 'index' is optional, and defaults to zero.
* 'index' can be supplied, to generate multiple keys for the same identity string.

.. _sign_identity_reply:

sign_identity reply
-------------------

* NOTE: The reply is not sent until the user has explicitly confirmed signing on the hw.

.. code-block:: cbor

    {
        "id": "50wtlyl",
        "result": {
            "signature": <65 bytes>
            "pubkey": <65 bytes>
        }
    }

* 'signature' is the low-s signature, prefixed with 0x00
* 'pubkey' is an uncompressed EC public key point
* This should be consistent with get_identity_pubkey_reply_ (with a 'type' of 'slip-0013') above.

.. _sign_message_legacy_request:

sign_message request (legacy)
-----------------------------

Request to sign a message string the given bip32 path, using RFC6979.

* This flow should be considered legacy - 'anti-exfil' signatures should be preferred.  See sign_message_ae_request_.

.. code-block:: cbor

    {
        "id": "6979",
        "method": "sign_message",
        "params": {
            "message": "Message to sign",
            "path": [2147483697, 2147483648, 2147483648, 0, 143]
        }
    }

 or:

.. code-block:: cbor

    {
        "id": "6979",
        "method": "sign_message"
        "params": {
            "message_file": "signmessage m/84h/0h/0h/0/0 ascii:this is a test message"
        }
    }


.. _sign_message_legacy_reply:

sign_message reply (legacy)
---------------------------

* NOTE: The reply is not sent until the user has explicitly confirmed signing on the hw.

.. code-block:: cbor

    {
        "id": "6979",
        "result": "H/bXtGN8FhkaPkLwKCZf4+AISH+SrCRnwpBNXxMxO/W5QRMDPKqJAjJGnRMqO+RusL9fQwlG7EtMOhbITiBPxWs="
    }

* 'result' is a base64-encoded signature.

.. _sign_message_ae_request:

sign_message request (anti-exfil)
---------------------------------

Request to sign a message string the given bip32 path, using anti-exfil commitments (recommended).

.. code-block:: cbor

    {
        "id": "57",
        "method": "sign_message",
        "params": {
            "message": "Message to sign",
            "path": [2147483697, 2147483648, 2147483648, 0, 143],
            "ae_host_commitment": <32 bytes>
        }
    }

.. _sign_message_ae_reply:

sign_message reply (anti-exfil)
-------------------------------

* NOTE: The reply is not sent until the user has explicitly confirmed signing on the hw.

.. code-block:: cbor

    {
        "id": "57",
        "result": "<32 bytes>"
    }

* In the case of Anti-Exfil signing, the inital returned data is the 'signer commitment' bytes (which the caller can use later to verify the AE signature).

The caller must then send a 'get_signature' message, passing the 'host entropy'.

.. _sign_message_ae_get_signature_request:

get_signature request (sign-message)
------------------------------------

Request to fetch an Anti-Exfil signature, providing the 'host entropy'.

.. code-block:: cbor

    {
        "id": "64",
        "method": "get_signature",
        "params": {
            "ae_host_entropy": <32 bytes>
        }
    }

.. _sign_message_ae_get_signature_reply:

get_signature reply (sign_message)
----------------------------------

.. code-block:: cbor

    {
        "id": "64",
        "result": "H/bXtGN8FhkaPkLwKCZf4+AISH+SrCRnwpBNXxMxO/W5QRMDPKqJAjJGnRMqO+RusL9fQwlG7EtMOhbITiBPxWs="
    }

* 'result' is a base64-encoded signature.

.. _sign_tx_legacy_request:

sign_tx request (legacy)
------------------------

Request to sign transaction inputs using RFC6979.

* This flow should be considered legacy - 'anti-exfil' signatures should be preferred.  See sign_tx_ae_request_.

.. code-block:: cbor

    {
        "id": "86400",
        "method": "sign_tx",
        "params": {
            "network": "mainnet",
            "txn": <bytes>,
            "num_inputs": 2,
            "use_ae_signatures": false,
            "change": [
                null,
                {
                    "variant": "sh(wpkh(k))",
                    "path": [2147483697, 2147483648, 2147483648, 0, 143]
                },
                null
            ]
        }
    }

* 'txn' should be the raw txn bytes.
* 'num_inputs' is the number of input messages which will be sent - which must be equal to the number of inputs in the transaction 'txn'.
* 'change' is optional (or can be null) - if provided it should be an array with the same number of elements as there are tx outputs.
* 'change' elements should be null for most outputs, and only populated for the outputs Jade is to automatically verify belong to its wallet.
* If 'is_change' is set (or missing - if so it is assumed to be true) this output will not be shown to the user to verify.
* The populated 'change' element should contain the data used to generate the output script (see also get_receive_address_request_):

Blockstream Green address (multisig-shield):

.. code-block:: cbor

    {
        "path": [1, 1, 13]
        "recovery_xpub": None
        "csv_blocks": 65535
    }

* 'recovery_xpub' is required if the change is to a 2of3 subaccount, otherwise should be omitted.
* 'csv_blocks' is required for csv-enabled accounts, otherwise should be omitted.

single-sig:

.. code-block:: cbor

    {
        "variant": "sh(wpkh(k))",
        "path": [2147483697, 2147483648, 2147483648, 0, 143]
    }

multi-sig:

.. code-block:: cbor

    {
        "multisig_name": "small_beans",
        "paths": [ [0,1], [0,1] ]
    }
  
.. _sign_tx_legacy_reply:

sign_tx reply (legacy)
----------------------

* NOTE: The reply is not sent until the user has explicitly confirmed the outputs on the hw.

.. code-block:: cbor

    {
        "id": "86400",
        "result": true
    }

At this point, the details of the tx-inputs must be sent to Jade for signing.

.. _sign_tx_legacy_input_request:

sign_tx input request (legacy)
------------------------------

A batch of 'tx_input' messages should be sent to Jade - one for each tx input.

* NOTE: No replies will be sent until the entire batch has been processed and confirmed on Jade.

.. code-block:: cbor

    {
        "id": "86400000000",
        "method": "tx_input",
        "params": {
            "is_witness": false,
            "input_tx": <bytes>,
            "script": <bytes>,
            "path": [2147483697, 2147483648, 2147483648, 0, 34],
            "sighash": 2
        }
    }

* 'is_witness', 'script', 'path' and 'sighash' should be omitted if a signature for this input is not required.
* 'sighash' is optional, and defaults to 1 (SIGHASH_ALL)
* If provided, 'script' should be the script-sig/redeem-script required to satisfy the input utxo.
* 'input_tx' should be the streamed bytes of the txn which output the utxo being spent.
* NOTE: if this is the only input, and 'is_witness' is 'true', the 'input_tx' can (optionally) be replaced with a 'satoshi' element, eg: '"satoshi": 2200000'.

Once the entire batch (of 'tx_input' messages) has been sent, processed and confirmed on Jade, a batch of replies are sent.

.. _sign_tx_legacy_input_reply:

sign_tx input reply (legacy)
----------------------------

The batch of replies should contain the same number of messages as the number of 'tx_input' messages sent, and the order of replies corresponds to the order of input messages (order of inputs in the txn).

.. code-block:: cbor

    {
        "id": "86400000000",
        "result": <bytes>
    }

* 'result' will be the bytes for the signature for the corresponding input, in DER format with the sighash appended.
* 'result' will be empty, if no signature was required for this input.

.. _sign_tx_ae_request:

sign_tx request (anti-exfil)
----------------------------

To use Anti-Exfil signatures (recommended), the the initial request is the same as in sign_tx_legacy_request_, except the 'use_ae_signatures' field should be set to 'true'.

.. _sign_tx_ae_reply:

sign_tx reply (anti-exfil)
--------------------------

The initial reply is the same as in sign_tx_legacy_reply_.

.. code-block:: cbor

    {
        "id": "86400",
        "result": true
    }

At this point, the details of the tx-inputs must be sent to Jade for signing.

sign_tx input request (anti-exfil)
----------------------------------

As in sign_tx_legacy_input_request_, 'tx_input' messages should be sent to Jade - one for each tx input.
However, in this case the message must include the 'ae_host_commitment'.

.. code-block:: cbor

    {
        "id": "THX1138",
        "method": "tx_input",
        "params": {
            "is_witness": false,
            "input_tx": <bytes>,
            "script": <bytes>,
            "path": [2147483697, 2147483648, 2147483648, 0, 34],
            "sighash": 3,
            "ae_host_commitment": <32 bytes>
        }
    }


* NOTE: in the Anti-Exfil flow the reply will be sent immediately, and does not wait for all inputs to be sent.

.. _sign_tx_ae_input_reply:

sign_tx input reply (anti-exfil)
--------------------------------

.. code-block:: cbor

    {
        "id": "THX1138",
        "result": <32 bytes>
    }

* In the case of Anti-Exfil signing, the inital returned data is the 'signer commitment' bytes (which the caller can use later to verify the AE signature).
* 'result' will be empty, if no signature was required for this input.

Once all 'tx_input' messages have been sent, the caller must then send a 'get_signature' message for each input, passing the 'host entropy'.

.. _sign_tx_ae_get_signature_request:

get_signature request (sign_tx)
-------------------------------

* NOTE: The first reply is not sent until the user has explicitly confirmed signing on the hw.

Request to fetch an Anti-Exfil signature, providing the 'host entropy' (as in sign_message_ae_get_signature_request_).

.. code-block:: cbor

    {
        "id": "128",
        "method": "get_signature",
        "params": {
            "ae_host_entropy": <32 bytes>
        }
    }

The reply is then sent immediately.

.. _sign_tx_ae_get_signature_reply:

get_signature reply (sign_tx)
-----------------------------

.. code-block:: cbor

    {
        "id": "128",
        "result": <bytes>
    }

* 'result' will be the bytes for the signature for the corresponding input, in DER format with the sighash appended.
* 'result' will be empty, if no signature was required for this input.


Blockstream Liquid specific
===========================

.. _get_master_blinding_key_request:

get_master_blinding_key request
-------------------------------

Used to fetch the master (SLIP-077) blinding key for the wallet.
May block temporarily while asking the user to confirm the export from Jade.
Passing 'only_if_silent' will instead immediately return a 'denied' error if it would usually need to ask the user to confirm.

.. code-block:: cbor

    {
        "id": "66",
        "method": "get_master_blinding_key"
        "params": {
            "only_if_silent": False
        }
    }

* Passing 'only_if_silent' as True means the call will always return immediately - it will return the 'denied' error if it would normally ask the user to confirm.
* Passing 'only_if_silent' as False (or not passing it at all) allows the call to block temporarily if asking the user to confirm the export is required.

.. _get_master_blinding_key_reply:

get_master_blinding_key reply
-----------------------------

* NOTE: The reply is not sent until the user has explicitly confirmed on the hw.

.. code-block:: cbor

    {
        "id": "66",
        "result": <32 bytes>
    }

.. _get_blinding_key_request:

get_blinding_key request
------------------------

Used to fetch a script-specific public blinding key.

.. code-block:: cbor

    {
        "id": "365",
        "method": "get_blinding_key",
        "params": {
            "script": <bytes>
            "multisig_name": "small_beans"
        }
    }

* 'script' should be the raw bytes of the script for which the blinding key is required.
* 'multisig_name' is optional and defaults to null.  It is only used for registered multisig wallets.

.. _get_blinding_key_reply:

get_blinding_key reply
----------------------

.. code-block:: cbor

    {
        "id": "365",
        "result": <33 bytes>
    }

.. _get_shared_nonce_request:

get_shared_nonce request
------------------------

Used to fetch a script-specific blinding nonce.

.. code-block:: cbor

    {
        "id": "711",
        "method": "get_shared_nonce",
        "params": {
            "script": <bytes>,
            "their_pubkey": <33 bytes>,
            "include_pubkey": false
            "multisig_name": "small_beans"
        }
    }

* 'script' should be the raw bytes of the script for which the blinding key is required.
* 'their_pubkey' needs to be the EC public key of the counterparty for the given script.
* 'include_pubkey' is an optional boolean field.  If present and 'true' the reply will also include the public blinding key for the script (see get_blinding_key_request_).
* 'multisig_name' is optional and defaults to null.  It is only used for registered multisig wallets.
 
.. _get_shared_nonce_reply:

get_blinding_nonce reply
------------------------

When 'include_pubkey' not set, or 'false':

.. code-block:: cbor

    {
        "id": "711",
        "result": <32 bytes>
    }

When 'include_pubkey' present and 'true':

.. code-block:: cbor

    {
        "id": "711",
        "result": {
            "shared_nonce": <32 bytes>,
            "blinding_key": <33 bytes>
        }
    }

.. _get_blinding_factor_request:

get_blinding_factor request
---------------------------

Used to fetch a deterministic output blinding factor (abf/assetblinder or vbf/valueblinder).

.. code-block:: cbor

    {
        "id": "299792458",
        "method": "get_blinding_factor",
        "params": {
            "hash_prevouts": <32 bytes>
            "output_index": 1,
            "type": "VALUE",
            "multisig_name": "small_beans"
        }
    }

* 'hash_prevout' should be the double sha256 of the serialization of all input outpoints, as documented in bip143.
* 'type' must be either 'ASSET', 'VALUE', or 'ASSET_AND_VALUE'.
* 'multisig_name' is optional and defaults to null.  It is only used for registered multisig wallets.
 
.. _get_blinding_factor_reply:

get_blinding_factor reply
-------------------------

.. code-block:: cbor

    {
        "id": "299792458",
        "result": <32 or 64 bytes>
    }

* For 'ASSET' and 'VALUE' requests a 32-byte blinding factor is returned.
* For 'ASSET_AND_VALUE' requests a 64-byte abf|vbf value is returned - ie. the first 32 bytes are the abf, the second 32 bytes are the vbf.

.. _get_commitments_request:

get_commitments request
-----------------------

Used to fetch output commitments - ie. returns blinded output (and associated blinding factors).

.. code-block:: cbor

    {
        "id": "867-5309",
        "method": "get_commitments",
        "params": {
            "asset_id": <32 bytes>
            "value": 9000000,
            "hash_prevouts": <32 bytes>
            "output_index": 1,
            "vbf": <32 bytes>,
            "multisig_name": "small_beans"
        }
    }

* 'hash_prevout' should be the double sha256 of the serialization of all input out-points, as documented in bip143.
* 'vbf' is an optional override, and defaults to null, in which case the value is calculated.
* 'vbf' is provided for one output, so the tx commitment values sum correctly.
* 'multisig_name' is optional and defaults to null.  It is only used for registered multisig wallets.
 
.. _get_commitments_reply:

get_commitments reply
---------------------

.. code-block:: cbor

    {
        "id": "867-5309",
        "result": {
            "abf": <32 bytes>,
            "vbf": <32 bytes>,
            "asset_generator": <33 bytes>,
            "value_commitment": <33 bytes>,
            "asset_id": <32 bytes>,
            "value", 9000000
        }
    }

* NOTE: These commitments must be passed back to Jade when signing the liquid txn.

.. _sign_liquid_tx_legacy_request:

sign_liquid_tx request (legacy)
-------------------------------

Request to sign liquid transaction inputs.

* This flow should be considered legacy - 'anti-exfil' signatures should be preferred.  See sign_liquid_tx_ae_request_.
* NOTE: The data is similar to that described in sign_tx_legacy_request_ - with the addition of a 'trusted_commitments' array and an optional array of asset data.

.. code-block:: cbor

    {
        "id": "911",
        "method": "sign_liquid_tx",
        "params": {
            "network": "testnet-liquid",
            "txn": <bytes>,
            "num_inputs": 4,
            "use_ae_signatures": false,
            "change": [
                null,
                {
                    "variant": "sh(wpkh(k))",
                    "path": [2147483697, 2147483648, 2147483648, 0, 143],
                    "is_change": true
                },
                null
            ],
            "asset_info": [
                {
                    "asset_id": "38fca2d939696061a8f76d4e6b5eecd54e3b4221c846f24a6b279e79952850a5",
                    "contract": {
                        "entity": {
                            "domain": "liquidtestnet.com"
                        },
                        "issuer_pubkey": "035d0f7b0207d9cc68870abfef621692bce082084ed3ca0c1ae432dd12d889be01",
                        "name": "Testnet Asset",
                        "precision": 3,
                        "ticker": "TEST",
                        "version": 0
                    },
                    "issuance_prevout": {
                        "txid": "0e19e938c74378ae83b549213a12be88ede6e32e1407bfdf50c4ec3f927408ec",
                        "vout": 0
                    }
                }
            ],
            "trusted_commitments": [
                {
                    "abf": "308fee61c9b6f6ba534abefaa0e3fef58f5dc8b8a772135f157b3f771b005164",
                    "asset_generator": "0bacf4e230f12327ff795f8c814f80b0502e78683d067fe75ba38fd2d0be27188b",
                    "asset_id": "38fca2d939696061a8f76d4e6b5eecd54e3b4221c846f24a6b279e79952850a5",
                    "blinding_key": "03462d3febd7654b22c6faaf5d12a400693dbdf21f8cb9a82e18aba8457c6812d4",
                    "value": 50000000,
                    "value_commitment": <33 bytes>,
                    "vbf": <32 bytes>
                },
                {
                    "abf": "a3510210bbab6ed67429af9beaf42f09382e12146a3db466971b58a45516bba0",
                    "asset_generator": "0abd23178d9ff73cf848d8d88a7c7e269a464f53017cab0f9f53ed9d64b2849713",
                    "asset_id": "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49",
                    "blinding_key": "023454c233497be73ed98c07d5e9069e21519e94d0663375ca57c982037546e352",
                    "value": 9000000,
                    "value_commitment": "0881e4ace4be80524bcc4f566e46a452ab5f43a49929cbf5743d9e1de879a478a7",
                    "vbf": "6ec064a68075a278bfca4a10f777c730116e9ba02fbb343a237c847e4d2fbf53"
                },
                null
            ],
            "additional_info": {
                "tx_type": "swap",
                "wallet_input_summary": [
                    {
                        "asset_id": "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49",
                        "satoshi": 1000000
                    }
                ],
                "wallet_output_summary": [
                    {
                        "asset_id": "38fca2d939696061a8f76d4e6b5eecd54e3b4221c846f24a6b279e79952850a5",
                        "satoshi": 50000000
                    }
                ]
            }
        }
    }

* Most fields are as described in sign_tx_legacy_request_.
* 'asset_info' is optional, but if passed should be the asset-id, contract and issuance-prevout sections of the asset registry data pertinent to the assets being transacted.  If present, this allows the transaction details displayed on Jade to include assets' name, issuer and ticker fields, rather than just asset-id alone.  NOTE: if passed, this data must be accurate as obtained from the asset registry json, and the fields in the expected (ie. alphabetical) order.  'asset_info' for the network policy-asset is not required.
* 'trusted_commitments' must be passed in for each blinded output.  Where an output is not blinded (eg. fee output) null may be passed.
* 'trusted_commitments' entries passed in here can be obtained using the get_commitments_request_, with the relevant 'blinding_key' added (which would originally be obtained from get_blinding_key_request_).
* NOTE: as of Jade fw v0.1.34, external blinding is supported, in which case the 'trusted_commitments' can be constructed by the host application.  Note the 'asset_id' byte-order is that consistent with the registry data, but the 'abf' and 'vbf' fields need to be in the byte-order in which they would be used in the blinding (which may be reversed).
* 'additional_info' is only required for advanced transaction types such as asset swaps, and can be omitted for vanilla 'send payment' type transactions.  If included, it contains the net movements of assets into and out of the wallet (ie. sum of inputs minus change outputs, and sum of non-change outputs per asset)

.. _sign_liquid_tx_legacy_reply:

sign_liquid_tx reply (legacy)
-----------------------------

* As sign_tx_legacy_reply_
* NOTE: The reply is not sent until the user has explicitly confirmed the outputs on the hw.

.. code-block:: cbor

    {
        "id": "911",
        "result": true
    }

At this point, the details of the tx-inputs must be sent to Jade for signing.

.. _sign_liquid_tx_legacy_input_request:

sign_liquid_tx input request (legacy)
-------------------------------------

A batch of 'tx_input' messages should be sent to Jade - one for each tx input, as in sign_tx_legacy_input_request_.

* NOTE: No replies will be sent until the entire batch has been processed and confirmed on Jade.

.. code-block:: cbor

    {
        "id": "999",
        "method": "tx_input",
        "params": {
            "is_witness": true,
            "script": <bytes>,
            "value_commitment": <33 bytes>,
            "path": [2147483697, 2147483648, 2147483648, 0, 34],
            "sighash": 3
        }
    }

* 'is_witness', 'script', 'path' and 'sighash' are as in sign_tx_legacy_input_request_.
* In addition, if a signature is required for this input and 'is_witness' is 'true', then the input utxo 'value_commitment' must be passed.
* NOTE: no 'input_tx' is needed.
* For advanced tx types, eg swaps, with blinded inputs, we pass the unblinding info here.  ie. asset_id, abf, asset_generator, value and vbf - these are as in the 'commitments' data in sign_liquid_tx_legacy_request_.
Once the entire batch (of 'tx_input' messages) has been sent, processed and confirmed on Jade, a batch of replies are sent.

.. _sign_liquid_tx_legacy_input_reply:

sign_liquid_tx input reply (legacy)
-----------------------------------

* As sign_tx_legacy_input_reply_

The batch of replies should contain the same number of messages as the number of 'tx_input' messages sent, and the order of replies corresponds to the order of input messages (order of inputs in the txn).

.. code-block:: cbor

    {
        "id": "999",
        "result": <bytes>
    }

* 'result' will be the bytes for the signature for the corresponding input, in DER format with the sighash appended.
* 'result' will be empty, if no signature was required for this input.

.. _sign_liquid_tx_ae_request:

sign_liquid_tx request (anti-exfil)
-----------------------------------

To use Anti-Exfil signatures (recommended), the the initial request is the same as in sign_liquid_tx_legacy_request_, except the 'use_ae_signatures' field should be set to 'true'.

.. _sign_liquid_tx_ae_reply:

sign_liquid_tx reply (anti-exfil)
---------------------------------

The initial reply is the same as in sign_liquid_tx_legacy_reply_.

.. code-block:: cbor

    {
        "id": "911",
        "result": true
    }

At this point, the details of the tx-inputs must be sent to Jade for signing.

sign_liquid_tx input request (anti-exfil)
-----------------------------------------

As in sign_liquid_tx_legacy_input_request_, 'tx_input' messages should be sent to Jade - one for each tx input.
However, in this case the message must include the 'ae_host_commitment'.

.. code-block:: cbor

    {
        "id": "5040",
        "method": "tx_input",
        "params": {
            "is_witness": true,
            "script": <bytes>,
            "value_commitment": <33 bytes>,
            "path": [2147483697, 2147483648, 2147483648, 0, 34],
            "sighash": 2,
            "ae_host_commitment": <32 bytes>
        }
    }


* NOTE: in the Anti-Exfil flow the reply will be sent immediately, and does not wait for all inputs to be sent.

.. _sign_liquid_tx_ae_input_reply:

sign_liquid_tx input reply (anti-exfil)
---------------------------------------

* As sign_liquid_tx_legacy_input_reply_

.. code-block:: cbor

    {
        "id": "5040",
        "result": <32 bytes>
    }

* In the case of Anti-Exfil signing, the inital returned data is the 'signer commitment' bytes (which the caller can use later to verify the AE signature).
* 'result' will be empty, if no signature was required for this input.

Once all 'tx_input' messages have been sent, the caller must then send a 'get_signature' message for each input, passing the 'host entropy'.

.. _sign_liquid_tx_ae_get_signature_request:

get_signature request (sign_liquid_tx)
--------------------------------------

* As sign_tx_ae_get_signature_request_
* NOTE: The first reply is not sent until the user has explicitly confirmed signing on the hw.

Request to fetch an Anti-Exfil signature, providing the 'host entropy' (as in sign_message_ae_get_signature_request_).

.. code-block:: cbor

    {
        "id": "256",
        "method": "get_signature",
        "params": {
            "ae_host_entropy": <32 bytes>
        }
    }

The reply is then sent immediately.

.. _sign_liquid_tx_ae_get_signature_reply:

get_signature reply (sign_liquid_tx)
------------------------------------

* As sign_tx_ae_get_signature_reply_

.. code-block:: cbor

    {
        "id": "256",
        "result": <bytes>
    }

* 'result' will be the bytes for the signature for the corresponding input, in DER format with the sighash appended.
* 'result' will be empty, if no signature was required for this input.

.. _sign_psbt_request:

sign_psbt request
-----------------

Request to append signatures to a passed psbt, using RFC6979.

.. code-block:: cbor

    {
        "id": "6979",
        "method": "sign_psbt",
        "params": {
            "network": "mainnet",
            "psbt": <psbt bytes>
        }
    }

* Any inputs requiring signatures from this wallet (as identified by fingerprint) are generated and appended to the passed psbt.

.. _sign_psbt_reply:

sign_psbt
---------

* NOTE: The reply is not sent until the user has explicitly confirmed signing on the hw.

.. code-block:: cbor

    {
        "id": "6979",
        "seqnum": 1
        "seqlen": 4
        "result": <psbt bytes>
    }

* NOTE: 'seqnum' and 'seqlen' indicate if the data is complete.  If 'seqlen' is greater than 1, the caller will have to send 'get_extended_data' messages to fetch the complete data.  See get_extended_data_request_.
* 'result' is the input psbt updated with any generated signatures.
* NOTE: if 'get_extended_data' calls are needed, the bytes payload of the messages must be concatenated to yield the complete psbt.

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
