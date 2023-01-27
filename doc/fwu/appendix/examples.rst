.. SPDX-FileCopyrightText: Copyright 2020-2023 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. _examples:

Example usage
=============

.. warning::
   These examples are for illustrative purposes only and are not guaranteed to compile. Many error codes are not handled in order to keep the examples brief. A real implementation will need to initialize variables appropriately and handle failures as they see fit.

Retrieve versions of installed images
-------------------------------------

This example shows the retrieval of image versions for all components.

.. literalinclude:: /example/version_info.c
   :language: xref
   :linenos:
   :lines: 4-

Individual component update (single part operation)
---------------------------------------------------

This example shows the installation of a single component that is smaller than `PSA_FWU_MAX_WRITE_SIZE`.

.. literalinclude:: /example/single_image.c
   :language: xref
   :linenos:
   :lines: 4-

.. _example-multi-write:

Individual component update (multi part operation)
--------------------------------------------------

This example shows the installation of a component that can be larger than `PSA_FWU_MAX_WRITE_SIZE`, and requires writing in multiple blocks.

.. literalinclude:: /example/single_image_mutipart.c
   :language: xref
   :linenos:
   :lines: 4-

.. _multi-component-example:

Multiple components with dependent images
-----------------------------------------

This example shows how multiple components can be installed together. This is required if the images are inter-dependent, and it is not possible to install them in sequence because of the dependencies.

.. note::

   Not all implementations that have multiple components support this type of multi-component update.

.. literalinclude:: /example/multi_image_singlepart.c
   :language: xref
   :linenos:
   :lines: 4-

Clean up all component updates
------------------------------

This example removes any prepared and failed update images for all components.

.. literalinclude:: /example/clean_up.c
   :language: xref
   :linenos:
   :lines: 4-
