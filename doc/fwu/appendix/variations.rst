.. SPDX-FileCopyrightText: Copyright 2020-2023 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. _variations:

Variation in system design parameters
=====================================

Depending on the system design and product requirements, an implementation can collapse a chain of transitions for a component, where this does not remove information that is required by the update client, or compromise other system requirements. This can result in some states and transitions being eliminated from the state model for that component's firmware store.

An implementation is also permitted to provide either volatile or persistent staging for images that are being prepared. For components with volatile staging, additional transitions can occur at reboot, compared to the full state model described in :secref:`state-model`.

The following variations are described in this specification:

.. csv-table::
   :header-rows: 1
   :align: left
   :widths: 2 2 2 5

   Reboot required, Trial required, Staging type, Description
   Yes, Yes, Persistent, See :ref:`full state model <state-transitions>`
   Yes, Yes, Volatile, See :ref:`full state model with volatile staging <fig-states-volatile>`
   Yes, No, Persistent, See :ref:`no-trial model <states-reboot-no-trial>`
   Yes, No, Volatile, See :ref:`no-trial model with volatile staging <fig-states-no-trial-volatile>`
   No, Yes, Persistent, See :ref:`no-reboot model <states-no-reboot-trial>`
   No, Yes, Volatile, See :ref:`no-reboot model with volatile staging <fig-states-no-reboot-volatile>`
   No, No, Persistent, See :ref:`basic state model <states-no-reboot-no-trial>`
   No, No, Volatile, See :ref:`basic state model with volatile staging <fig-states-no-reboot-no-trial-volatile>`


Components that have persistent staging
---------------------------------------

Components that do not have the `PSA_FWU_FLAG_VOLATILE_STAGING` flag set in the information reported by `psa_fwu_query()`, will maintain the component state across a reboot.

.. _states-reboot-no-trial:

Components that require a reboot, but no trial
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If a component does not require testing before committing the update, the the TRIAL and REJECTED states are not used. The ``reboot`` operation that installs the firmware will transition to UPDATED on success, or FAILED on failure. The ``accept`` operation is never used, the ``reject`` operation is still used to abandon an update that has been STAGED.

The simplified flow is shown in :numref:`fig-states-no-trial`.

.. figure:: /figure/fwu-states-no-trial.*
   :name: fig-states-no-trial
   :scale: 90%

   State model for a component that does not require a trial

.. _states-no-reboot-trial:

Components that require a trial, but no reboot
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If a component does not require a reboot to complete installation, the STAGED state is not required. The ``install`` operation will complete the installation immediately, transitioning to TRIAL if successful.

This use case also removes the REJECTED state, because the ``reject`` operation from TRIAL state does not require a ``reboot`` to complete.a A ``reject`` operation from TRIAL states transitions directly to FAILED.

The simplified flow is shown in :numref:`fig-states-no-reboot`:

.. figure:: /figure/fwu-states-no-reboot.*
   :name: fig-states-no-reboot
   :scale: 90%

   State model for a component that does not require a reboot

.. admonition:: Implementation note

   There is no ability for the update service to automatically reject a TRIAL, because the "``reboot`` without ``accept``" condition used for this purpose in the full state model is not available in this use case.

.. _states-no-reboot-no-trial:

Components that require neither a reboot, nor a trial
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If a component does not require a reboot to complete installation, and does not require testing before committing the update, then the STAGED, TRIAL, and REJECTED states are not required. The ``install`` operation will complete the installation immediately, transitioning to UPDATED if successful. The ``accept`` and ``reject`` operations are not used.

The simplified flow is shown in :numref:`fig-states-no-reboot-no-trial`:

.. figure:: /figure/fwu-states-no-reboot-no-trial.*
   :name: fig-states-no-reboot-no-trial
   :scale: 90%

   State model for a component that does not require a reboot or trial

.. _variations-volatile:

Components that have volatile staging
-------------------------------------

Components that have the `PSA_FWU_FLAG_VOLATILE_STAGING` flag set in the information reported by `psa_fwu_query()`, do not maintain the component state across a reboot.

For such a component, all the component states, except READY, are transient. In each case the state model is very similar to the associated state model for a component with persistent staging, except that a reboot now affects almost all states:

1. WRITING, CANDIDATE, and FAILED states will revert to READY, discarding any image that had been prepared or rejected.
2. UPDATED state is progressed to READY.
3. Existing reboot transitions from STAGED, TRIAL, and REJECTED, that go to FAILED in the persistent-staging model, are reverted to READY.
4. The existing reboot transition from STAGED to UPDATED for a successful installation in the 'no trial' model, transitions to READY.

The modified flows are shown in the following figures:

*  Modified reboot transitions are shown explicitly in the diagrams.
*  New reboot transitions are indicated with '*', '†', and '‡' marks on the state, and described in the diagram legend.

.. figure:: /figure/fwu-states-volatile.*
   :name: fig-states-volatile
   :scale: 90%

   Full state model for a component with volatile staging

.. figure:: /figure/fwu-states-no-trial-volatile.*
   :name: fig-states-no-trial-volatile
   :scale: 90%

   State model for a component with volatile staging that does not require a trial

.. figure:: /figure/fwu-states-no-reboot-volatile.*
   :name: fig-states-no-reboot-volatile
   :scale: 90%

   State model for a component with volatile staging that does not require a reboot

.. figure:: /figure/fwu-states-no-reboot-no-trial-volatile.*
   :name: fig-states-no-reboot-no-trial-volatile
   :scale: 90%

   State model for a component with volatile staging that does not require a reboot or trial
