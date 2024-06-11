.. SPDX-FileCopyrightText: Copyright 2018-2024 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

|API| library
=============

.. header:: psa/crypto
    :seq: 1
    :copyright: Copyright 2018-2024 Arm Limited and/or its affiliates <open-source-office@arm.com>
    :license: Apache-2.0
    :c++:
    :guard:
    :system-include: stddef.h stdint.h
    :include: psa/error.h

    /* This file is a reference template for implementation of the
     * PSA Certified Crypto API v1.3
     */


.. _api-version:

API version
-----------

.. macro:: PSA_CRYPTO_API_VERSION_MAJOR
    :api-version: major

    .. summary::
        The major version of this implementation of the Crypto API.

.. macro:: PSA_CRYPTO_API_VERSION_MINOR
    :api-version: minor

    .. summary::
        The minor version of this implementation of the Crypto API.

.. _library-init:

Library initialization
----------------------

.. function:: psa_crypto_init

    .. summary::
        Library initialization.

    .. return:: psa_status_t
    .. retval:: PSA_SUCCESS
        Success.
    .. retval:: PSA_ERROR_INSUFFICIENT_MEMORY
    .. retval:: PSA_ERROR_COMMUNICATION_FAILURE
    .. retval:: PSA_ERROR_CORRUPTION_DETECTED
    .. retval:: PSA_ERROR_INSUFFICIENT_ENTROPY

    It is recommended that applications call this function before calling any other function in this module.

    Applications are permitted to call this function more than once. Once a call succeeds, subsequent calls are guaranteed to succeed.

    If the application calls any function that returns a :code:`psa_status_t` result code before calling `psa_crypto_init()`, the following will occur:

    *   If initialization of the library is essential for secure operation of the function, the implementation must return :code:`PSA_ERROR_BAD_STATE` or other appropriate error.

    *   If failure to initialize the library does not compromise the security of the function, the implementation must either provide the expected result for the function, or return :code:`PSA_ERROR_BAD_STATE` or other appropriate error.

    .. note::

        The following scenarios are examples where an implementation can require that the library has been initialized by calling `psa_crypto_init()`:

        *   A client-server implementation, in which `psa_crypto_init()` establishes the communication with the server. No key management or cryptographic operation can be performed until this is done.

        *   An implementation in which `psa_crypto_init()` initializes the random bit generator, and no operations that require the RNG can be performed until this is done. For example, random data, key, IV, or nonce generation; randomized signature or encryption; and algorithms that are implemented with blinding.

    .. warning::
        The set of functions that depend on successful initialization of the library is :scterm:`IMPLEMENTATION DEFINED`. Applications that rely on calling functions before initializing the library might not be portable to other implementations.


Interruptible operation limit
-----------------------------

Using an interruptible operation, an application can perform an expensive cryptographic computation while limiting the execution time of each function call. The execution limit is controlled via the *maximum ops* value.

See :secref:`interruptible-operations`.

.. function:: psa_iop_set_max_ops

    .. summary::
        Set the maximum number of *ops* allowed to be executed by an interruptible function in a single call.

    .. param:: uint32_t max_ops
        The maximum number of ops to be executed in a single call, this can be a number from ``0`` to `PSA_IOP_MAX_OPS_UNLIMITED`, where ``0`` is obviously the least amount of work done per call.

    .. return:: void

    Interruptible functions use this value to limit the computation that is done in any single call to the function. If this limit is reached, the function will return :code:`PSA_OPERATION_INCOMPLETE`, and the caller must repeat the function call until a different status code is returned, or abort the operation.

    After initialization of the implementation, the maximum *ops* defaults to `PSA_IOP_MAX_OPS_UNLIMITED`. This means that the whole operation will complete in a single call, regardless of the number of *ops* required. An application must call `psa_iop_set_max_ops()` to set a different limit.

    .. note::

        The time taken to execute a single *op* is implementation specific and depends on software, hardware, the algorithm, key type and curve chosen. Even within a single operation, successive ops can take differing amounts of time. The only guarantee is that lower values for ``max_ops`` means functions will block for a lesser maximum amount of time and conversely larger values will mean blocking for a larger maximum amount of time. The functions `psa_sign_iop_get_num_ops()` and `psa_verify_iop_get_num_ops()` are provided to help with tuning this value.

    .. admonition:: Implementation note

        The interpretation of this maximum number is obviously also implementation defined. On a hard real-time system, this can indicate a hard deadline, which is good, as a real-time system needs a guarantee of not spending more than X time, however care must be taken to avoid the situation whereby calls just return, not being able to do any actual work within the allotted time.  On a non-real-time system, the implementation can be more relaxed, but again whether this number should be interpreted as as hard or soft limit or even whether a less than or equals as regards to ops executed in a single call is implementation defined.

    .. warning::
        With implementations that interpret this number as a hard limit, setting this number too small can result in an infinite loop, whereby each call results in immediate return with no computation done.

.. function:: psa_iop_get_max_ops

    .. summary::
       Get the maximum number of *ops* allowed to be executed by an interruptible function in a single call.

    .. return:: uint32_t
       Maximum number of *ops* allowed to be executed by an interruptible function in a single call.

    This returns the value last set in a call to `psa_iop_set_max_ops()`.

.. macro:: PSA_IOP_MAX_OPS_UNLIMITED
    :definition: UINT32_MAX

    .. summary::

        Maximum value for use with `psa_iop_set_max_ops()`.

    Using this value in a call to `psa_iop_set_max_ops()` will cause interruptible functions to complete their calculation before returning.
