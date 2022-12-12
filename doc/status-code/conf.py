# SPDX-FileCopyrightText: Copyright 2022 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

# PSA Certified API document configuration
#
# This is used to generate all of the sphinx configuration data and determine
# the document file name etc.

doc_info = {
    # Document template
    'template': 'psa-api-2022',

    # Document title, MANDATORY
    'title': 'PSA Certified\nStatus code API',
    'author': 'Arm Limited',

    # Document copyright date, default to year of 'date'
    'copyright_date': '2017-2022',
    'copyright': 'Arm Limited and/or its affiliates',

    # Arm document identifier, marked as open issue if not provided
    'doc_id': 'IHI 0097',

    # The short X.Y version. MANDATORY
    'version': '1.0',
    # Arm document quality status, marked as open issue if not provided
    'quality': 'REL',
    # Arm document issue number (within that version and quality status)
    # Marked as open issue if not provided
    'issue_no': 2,
    # Identifies the sequence number of a release candidate of the same issue
    # default to None
    'release_candidate': None,
    'draft': False,

    # Arm document confidentiality. Must be either Non-confidential or Confidential
    # Marked as open issue if not provided
    'confidentiality': 'Non-confidential',

    # Id of the legal notice for this document
    # Marked as open issue if not provided
    'license': 'psa-certified-api-license',

    # Document date, default to build date
    'date': '14/12/2022',

    # psa_spec: default header file for API definitions
    # default to None, and can be set in documentation source
    'header': 'psa/error',

    # Doxygen annotation level of the generated header
    #    0 : None (default)
    #    1 : Primary API elements
    #    2 : Sub-elements of API - parameters, fields, values
    'header_doxygen': 2,

    # Declare a watermark for the PDF output
    #'watermark': 'DRAFT',

    # List of optional content that should be included in the build.
    # Valid options are:
    #   'rationale' : This enables output of ..rationale:: directives
    'include_content': [],

    # Include the C Identifier index. Default to True
    'identifier_index': False,

    # Specify where to add page breaks in main/appendix
    #   'none'     : no page breaks
    #   'appendix' : just before the appendices
    #   'chapter'  : before every chapter
    # Default to 'appendix'
    'page_break': 'chapter',
    }

# If the draft flag is set, then include extra content and watermark

if doc_info.get('draft'):
    doc_info.pop('date', None)                      # Remove any release date - use build date
    doc_info['include_content'] = ['rationale', 'todo', 'banner']
    doc_info['watermark'] = "DRAFT"

# If a release candidate, then include watermark

if doc_info.get('release_candidate'):
    doc_info['watermark'] = "Candidate"

# absolute or relative path to the psa_spec material from this file
# atg_sphinx_spec_dir = '../atg-sphinx-spec'

# Set up and run the atg-sphinx-spec configuration

import os

atg_sphinx_spec_dir = os.environ.get('ATG_SPHINX_SPEC') or atg_sphinx_spec_dir
exec(compile(open(os.path.join(atg_sphinx_spec_dir,'atg-sphinx-conf.py'),
                  encoding='utf-8').read(),
             'atg-sphinx-conf.py', 'exec'))
