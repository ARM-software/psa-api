.. SPDX-FileCopyrightText: Copyright 2018-2022 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. _usage-considerations:

Usage considerations
--------------------

Security recommendations
~~~~~~~~~~~~~~~~~~~~~~~~

Always check for errors
^^^^^^^^^^^^^^^^^^^^^^^

Most functions in the |API| can return errors. All functions that can fail have
the return type :code:`psa_status_t`. A few functions cannot fail, and thus, return
``void`` or some other type.

If an error occurs, unless otherwise specified, the content of the output
parameters is undefined and must not be used.

Some common causes of errors include:

*   In implementations where the keys are stored and processed in a separate
    environment from the application, all functions that need to access the
    cryptography processing environment might fail due to an error in the
    communication between the two environments.
*   If an algorithm is implemented with a hardware accelerator, which is
    logically separate from the application processor, the accelerator might fail,
    even when the application processor keeps running normally.
*   Most functions might fail due to a lack of resources. However, some
    implementations guarantee that certain functions always have sufficient
    memory.
*   All functions that access persistent keys might fail due to a storage failure.
*   All functions that require randomness might fail due to a lack of entropy.
    Implementations are encouraged to seed the random generator with sufficient
    entropy during the execution of `psa_crypto_init()`. However, some security
    standards require periodic reseeding from a hardware random generator, which
    can fail.

Shared memory and concurrency
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Some environments allow applications to be multithreaded, while others do not.
In some environments, applications can share memory with a different security
context. In environments with multithreaded applications or shared memory,
applications must be written carefully to avoid data corruption or leakage. This
specification requires the application to obey certain constraints.

In general, the |API| allows either one writer or any number of simultaneous
readers, on any given object. In other words, if two or more calls access the
same object concurrently, then the behavior is only well-defined if all the
calls are only reading from the object and do not modify it. Read accesses
include reading memory by input parameters and reading keystore content by using
a key. For more details, refer to :secref:`concurrency`.

If an application shares memory with another security context, it can pass
shared memory blocks as input buffers or output buffers, but not as non-buffer
parameters. For more details, refer to :secref:`stability-of-parameters`.

Cleaning up after use
^^^^^^^^^^^^^^^^^^^^^

To minimize impact if the system is compromised, it is recommended that
applications wipe all sensitive data from memory when it is no longer used. That
way, only data that is currently in use can be leaked, and past data is not
compromised.

Wiping sensitive data includes:

*   Clearing temporary buffers in the stack or on the heap.
*   Aborting operations if they will not be finished.
*   Destroying keys that are no longer used.
