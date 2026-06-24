# SPDX-FileCopyrightText: Copyright 2018-2026 Arm Limited
# SPDX-License-Identifier: Apache-2.0

# Compatibility wrapper for older specification sources that still execute
# atg-sphinx-conf.py from the former atg-sphinx-spec tool.

import os

psa_api_tool_path = (os.environ.get('PSA_API_TOOL') or
                     os.environ.get('ATG_SPHINX_SPEC') or
                     globals().get('atg_sphinx_spec_dir'))

if not psa_api_tool_path:
    raise RuntimeError('PSA_API_TOOL or ATG_SPHINX_SPEC must point to psa-api-tool')

exec(compile(open(os.path.join(psa_api_tool_path, 'psa-api-conf.py'),
                  encoding='utf-8').read(),
             'psa-api-conf.py', 'exec'))
