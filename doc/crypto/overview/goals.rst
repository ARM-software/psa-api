.. SPDX-FileCopyrightText: Copyright 2018-2022 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. _design-goals:

Design goals
------------

.. _scalable:

Suitable for constrained devices
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The interface is suitable for a vast range of devices: from special-purpose
cryptographic processors that process data with a built-in key, to constrained
devices running custom application code, such as microcontrollers, and
multi-application devices, such as servers. Consequentially, the interface is
scalable and modular.

*   *Scalable*: devices only need to implement the functionality that they will
    use.
*   *Modular*: larger devices implement larger subsets of the same interface,
    rather than different interfaces.

In this interface, all operations on unbounded amounts of data
allow *multi-part* processing, as long as the calculations on the data are
performed in a streaming manner. This means that the application does not need
to store the whole message in memory at one time. As a result, this
specification is suitable for very constrained devices, including those where
memory is very limited.

Memory outside the keystore boundary is managed by the application. An
implementation of the interface is not required to retain any state between
function calls, apart from the content of the keystore and other data that must
be kept inside the keystore security boundary.

The interface does not expose the representation of keys and intermediate data,
except when required for interchange. This allows each implementation to choose
optimal data representations. Implementations with multiple components are also
free to choose which memory area to use for internal data.

.. _keystore:

A keystore interface
~~~~~~~~~~~~~~~~~~~~

The specification allows cryptographic operations to be performed on a key to
which the application does not have direct access. Except where required for
interchange, applications access all keys indirectly, by an identifier. The key
material corresponding to that identifier can reside inside a security boundary
that prevents it from being extracted, except as permitted by a policy that is
defined when the key is created.

.. _isolation:

Optional isolation
~~~~~~~~~~~~~~~~~~

Implementations can isolate the cryptoprocessor from the calling application,
and can further isolate multiple calling applications. The interface allows the
implementation to be separated between a frontend and a backend. In an isolated
implementation, the frontend is the part of the implementation that is located
in the same isolation boundary as the application, which the application
accesses by function calls. The backend is the part of the implementation that
is located in a different environment, which is protected from the frontend.
Various technologies can provide protection, for example:

*   Process isolation in an operating system.
*   Partition isolation, either with a virtual machine or a partition manager.
*   Physical separation between devices.

Communication between the frontend and backend is beyond the scope of this
specification.

In an isolated implementation, the backend can serve more than one
implementation instance. In this case, a single backend communicates with
multiple instances of the frontend. The backend must enforce :term:`caller isolation`:
it must ensure that assets of one frontend are not visible to any
other frontend. The mechanism for identifying callers is beyond the scope of this
specification. An implementation that provides caller isolation must document
the identification mechanism. An implementation that provides caller isolation must
document any implementation-specific extension of the API that enables frontend
instances to share data in any form.

An isolated implementation that only has a single frontend provides :term:`cryptoprocessor isolation`.

In summary, there are three types of implementation:

*   :term:`No isolation`: there is no security boundary between the application and the
    cryptoprocessor. For example, a statically or dynamically linked library is
    an implementation with no isolation.

*   :term:`Cryptoprocessor isolation`: there is a security boundary between the
    application and the cryptoprocessor, but the cryptoprocessor does not
    communicate with other applications. For example, a cryptoprocessor chip that
    is a companion to an application processor is an implementation with
    cryptoprocessor isolation.

*   :term:`Caller isolation`: there are multiple application instances, with a security
    boundary between the application instances among themselves, as well as
    between the cryptoprocessor and the application instances. For example, a
    cryptography service in a multiprocess environment is an implementation with
    caller and cryptoprocessor isolation.

.. _algorithm-agility:

Choice of algorithms
~~~~~~~~~~~~~~~~~~~~

The specification defines a low-level cryptographic interface, where the caller
explicitly chooses which algorithm and which security parameters they use. This
is necessary to implement protocols that are inescapable in various use cases.
The design of the interface enables applications to implement widely-used
protocols and data exchange formats, as well as custom ones.

As a consequence, all cryptographic functionality operates according to the
precise algorithm specified by the caller. However, this does not apply to
device-internal functionality, which does not involve any form of
interoperability, such as random number generation. The specification does not
include generic higher-level interfaces, where the implementation chooses the
best algorithm for a purpose. However, higher-level libraries can be built on
top of the |API|.

Another consequence is that the specification permits the use of algorithms, key
sizes and other parameters that, while known to be insecure, might be necessary to
support legacy protocols or legacy data. Where major weaknesses are known, the
algorithm descriptions give applicable warnings. However, the lack of a warning
both does not and cannot indicate that an algorithm is secure in all circumstances.
Application developers need to research the security of the protocols and
algorithms that they plan to use to determine if these meet their requirements.

The interface facilitates algorithm agility. As a consequence, cryptographic
primitives are presented through generic functions with a parameter indicating
the specific choice of algorithm. For example, there is a single function to
calculate a message digest, which takes a parameter that identifies the specific
hash algorithm.

.. _usability:

Ease of use
~~~~~~~~~~~

The interface is designed to be as user-friendly as possible, given the
aforementioned constraints on suitability for various types of devices and on
the freedom to choose algorithms.

In particular, the code flows are designed to reduce the risk of dangerous
misuse. The interface is designed in part to make it harder to misuse. Where
possible, it is designed so that
typical mistakes result in test failures, rather than subtle security issues.
Implementations avoid leaking data when a function is called with invalid
parameters, to the extent allowed by the C language and by implementation size
constraints.

Example use cases
~~~~~~~~~~~~~~~~~

This section lists some of the use cases that were considered during the design
of the |API|. This list is not exhaustive, nor are all implementations required to
support all use cases.

Network Security (TLS)
^^^^^^^^^^^^^^^^^^^^^^

The API provides all of the cryptographic primitives needed to establish TLS
connections.

Secure Storage
^^^^^^^^^^^^^^

The API provides all primitives related to storage encryption, block or
file-based, with master encryption keys stored inside a key store.

Network Credentials
^^^^^^^^^^^^^^^^^^^

The API provides network credential management inside a key store, for example,
for X.509-based authentication or pre-shared keys on enterprise networks.

Device Pairing
^^^^^^^^^^^^^^

The API provides support for key-agreement protocols that are often used for
secure pairing of devices over wireless channels. For example, the pairing of an
NFC token or a Bluetooth device might use key-agreement protocols upon
first use.

Secure Boot
^^^^^^^^^^^

The API provides primitives for use during firmware integrity and authenticity
validation, during a secure or trusted boot process.

Attestation
^^^^^^^^^^^

The API provides primitives used in attestation activities. Attestation is the
ability for a device to sign an array of bytes with a device private key and
return the result to the caller. There are several use cases; ranging from attestation
of the device state, to the ability to generate a key pair and prove that it has
been generated inside a secure key store. The API provides access to the
algorithms commonly used for attestation.

Factory Provisioning
^^^^^^^^^^^^^^^^^^^^

Most IoT devices receive a unique identity during the factory provisioning
process, or once they have been deployed to the field. This API provides the APIs necessary for
populating a device with keys that represent that identity.
