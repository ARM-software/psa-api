.. SPDX-FileCopyrightText: Copyright 2020-2023 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. _variations:

Variation in system design parameters
=====================================

Depending on the system design and product requirements, an implementation is permitted to collapse a chain of transitions for a component, where this does not remove information that is required by the update client, or compromise other system requirements. This can result in some states and transitions being eliminated from the state model for that component's firmware store.

An implementation is also permitted to provide either volatile or persistent behavior for the WRITING, CANDIDATE, FAILED, and UPDATED states. See also :secref:`volatile-states`. Volatile states cause additional transitions to occur at reboot.

:numref:`tab-variations` lists a sample of the possible variations that are illustrated in this appendix, as well as the complete state model provided in :secref:`programming-model`.

.. csv-table:: Variations of the state model
   :name: tab-variations
   :class: longtable
   :header-rows: 1
   :align: left
   :widths: 2 2 2 5

   Reboot required, Trial required, Staging type :sup:`a`, Description
   Yes, Yes, Non-volatile, See :ref:`complete model <state-transitions>`
   Yes, Yes, Volatile, See :ref:`complete model with volatile staging <fig-states-volatile>`
   Yes, No, Non-volatile, See :ref:`no-trial model <states-reboot-no-trial>`
   Yes, No, Volatile, See :ref:`no-trial model with volatile staging <fig-states-no-trial-volatile>`
   No, Yes, Non-volatile, See :ref:`no-reboot model <states-no-reboot-trial>`
   No, Yes, Volatile, See :ref:`no-reboot model with volatile staging <fig-states-no-reboot-volatile>`
   No, No, Non-volatile, See :ref:`basic state model <states-no-reboot-no-trial>`
   No, No, Volatile, See :ref:`basic state model with volatile staging <fig-states-no-reboot-no-trial-volatile>`

a)
   If the staging type is volatile, then CANDIDATE, WRITING, FAILED, and UPDATED states are volatile.

   If the staging type is non-volatile, then CANDIDATE state is non-volatile, and it is :scterm:`implementation defined` whether WRITING, FAILED, and UPDATED states are volatile.

Component with non-volatile staging
-----------------------------------

A component that does not have :term:`volatile staging` will maintain the CANDIDATE component state across a reboot, and can optionally maintain the WRITING, FAILED, and UPDATED component states across a reboot.

*  Additional reboot transitions for states with optional volatility are indicated with '†' and '‡' marks on the state, and described in the figure legend.

See :secref:`variations-volatile` for example state models for a component that has volatile staging.

.. _states-reboot-no-trial:

Component that requires a reboot, but no trial
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If a component does not require testing before committing the update, the the TRIAL and REJECTED states are not used.

*  The reboot that installs the firmware will transition the component to UPDATED on success, or FAILED on failure, unless the target state is volatile, in which case the reboot will transition the component to READY.
*  The ``accept`` operation is never used.
*  The ``reject`` operation is only used to abandon an update that has been STAGED.

The simplified flow is shown in :numref:`fig-states-no-trial`.

.. figure:: /figure/states/no-trial.*
   :name: fig-states-no-trial
   :scale: 90%

   State model for a component that does not require a trial

.. _states-no-reboot-trial:

Component that requires a trial, but no reboot
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If a component does not require a reboot to complete installation, the STAGED and REJECTED states are not used.

*  The ``install`` operation will complete the installation immediately, transitioning to TRIAL if successful.
*  The ``reject`` operation from TRIAL state does not require a reboot to complete. A ``reject`` operation from TRIAL states transitions directly to FAILED.

The simplified flow is shown in :numref:`fig-states-no-reboot`:

.. figure:: /figure/states/no-reboot.*
   :name: fig-states-no-reboot
   :scale: 90%

   State model for a component that does not require a reboot

.. admonition:: Implementation note

   There is no ability for the update service to automatically reject a TRIAL, because a reboot does not affect this component's installation.

.. _states-no-reboot-no-trial:

Component that requires neither a reboot, nor a trial
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If a component does not require a reboot to complete installation, and does not require testing before committing the update, then the STAGED, TRIAL, and REJECTED states are not used.

*  The ``install`` operation will complete the installation immediately, transitioning to UPDATED if successful.
*  The ``accept`` and ``reject`` operations are not used.

The simplified flow is shown in :numref:`fig-states-no-reboot-no-trial`:

.. figure:: /figure/states/no-reboot-no-trial.*
   :name: fig-states-no-reboot-no-trial
   :scale: 90%

   State model for a component that does not require a reboot or trial

.. _variations-volatile:

Component with volatile staging
-------------------------------

A component that has :term:`volatile staging` does not maintain the WRITING, CANDIDATE, FAILED, and UPDATED component states across a reboot.

In each case the state model is very similar to the associated state model for a component with non-volatile staging, except that a reboot now affects almost all states:

*  WRITING, CANDIDATE, and FAILED states will always revert to READY, discarding any image that had been prepared or rejected.
*  UPDATED state is progressed to READY.
*  Existing reboot transitions from STAGED, TRIAL, and REJECTED, that go to FAILED in the non-volatile-staging model, are reverted to READY.
*  The existing reboot transition from STAGED to UPDATED for a successful installation in the 'no trial' model, transitions to READY.

The modified flows are shown in the following figures:

*  Modified reboot transitions are shown explicitly in the diagrams.
*  New reboot transitions are indicated with '*', '†', and '‡' marks on the state, and described in the diagram legend.

.. figure:: /figure/states/volatile.*
   :name: fig-states-volatile
   :scale: 90%

   Full state model for a component with volatile staging

.. figure:: /figure/states/no-trial-volatile.*
   :name: fig-states-no-trial-volatile
   :scale: 90%

   State model for a component with volatile staging that does not require a trial

.. figure:: /figure/states/no-reboot-volatile.*
   :name: fig-states-no-reboot-volatile
   :scale: 90%

   State model for a component with volatile staging that does not require a reboot

.. figure:: /figure/states/no-reboot-no-trial-volatile.*
   :name: fig-states-no-reboot-no-trial-volatile
   :scale: 90%

   State model for a component with volatile staging that does not require a reboot or trial
