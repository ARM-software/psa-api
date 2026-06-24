.. SPDX-FileCopyrightText: Copyright 2018-2026 Arm Limited
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. role:: anchor

.. _about-this-document:

===================
About this document
===================

.. insert-section:: Release information
    :section: release-info
    :break-after:

    The change history table lists the changes that have been made to this document.

    .. release-table:: Document revision history

.. only:: include_todo

    .. insert-section:: TODO items
        :section: todos
        :break-after:
        :not-in-toc:

        The following items are marked up as TODO in the document source:

        .. todolist::

.. insert-section:: |docfulltitle|
    :not-in-toc:

    Copyright © |doccopyright|. The copyright statement reflects the fact that some
    draft issues of this document have been released, to a limited circulation.

.. include-license::

.. _license:

.. insert-section:: License
   :section: license
   :class: license
   :break-after:

.. insert-section:: References
    :section: references

    This document refers to the following documents.

    .. reference-table:: Documents referenced by this document


.. insert-section:: Terms and abbreviations
    :section: terms

    This document uses the following terms and abbreviations.

    .. term-table:: Terms and abbreviations
        :sorted:

.. insert-section:: Potential for change
    :section: potential-for-change

    The contents of this specification are subject to change.

    In particular, the following may change:

    *   Feature addition, modification, or removal
    *   Parameter addition, modification, or removal
    *   Numerical values, encodings, bit maps

.. insert-section:: Conventions
    :section: conventions

    .. insert-section:: Typographical conventions

        The typographical conventions are:

        *italic*
            Introduces special terminology, and denotes citations.

        ``monospace``
            Used for assembler syntax descriptions, pseudocode, and source code examples.

            Also used in the main text for instruction mnemonics and for references to
            other items appearing in assembler syntax descriptions, pseudocode, and
            source code examples.

        :sc:`small capitals`
            Used for some common terms such as :sc:`implementation defined`.

            Used for a few terms that have specific technical meanings, and are included
            in the *Terms and abbreviations*.

        :issue:`Red text`
            Indicates an open issue.

        :anchor:`Blue text`
            Indicates a link. This can be

            * A cross-reference to another location within the document
            * A URL, for example :url:`example.com`

    .. insert-section:: Numbers

        Numbers are normally written in decimal. Binary numbers are preceded by 0b, and
        hexadecimal numbers by ``0x``.

        In both cases, the prefix and the associated value are written in a monospace
        font, for example ``0xFFFF0000``. To improve readability, long numbers can be
        written with an underscore separator between every four characters, for example
        ``0xFFFF_0000_0000_0000``. Ignore any underscores when interpreting the value of
        a number.

.. insert-section:: Current status and anticipated changes
    :section: current-status

.. _feedback:

.. insert-section:: Feedback
    :section: feedback

    We welcome feedback on the PSA Certified API documentation.

    If you have comments on the content of this book, visit :url:`github.com/arm-software/psa-api/issues` to create a new issue at the PSA Certified API GitHub project. Give:

    *   The title (|docfulltitle|).
    *   The number and issue (|docid| |docrelease|).
    *   The location in the document to which your comments apply.
    *   A concise explanation of your comments.

    We also welcome general suggestions for additions and improvements.
