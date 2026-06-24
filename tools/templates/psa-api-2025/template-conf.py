# SPDX-FileCopyrightText: Copyright 2018-2026 Arm Limited
# SPDX-License-Identifier: Apache-2.0

# -*- coding: utf-8 -*-
#
# Adjust or reset the template_info dictionary with customized
# sphinx configurations for this template

template_info['logo_file'] = 'ARM_LOGO-2025_INK_RGB'
template_info['html_theme'] = 'alabaster'
template_info['html_css_files'] = [
    ('https://fonts.googleapis.com', { 'rel': 'preconnect' }),
    ('https://fonts.gstatic.com', { 'rel': 'preconnect', 'crossorigin': None }),
    ('https://fonts.googleapis.com/css2?family=Lato:ital,wght@0,300;0,400;1,300;1,400&display=swap', { 'rel': 'stylesheet' }),
    ('https://fonts.googleapis.com/css2?family=Noto+Sans+Mono:ital,wght@0,300;0,400;1,300&display=swap', { 'rel': 'stylesheet' })
]
template_info['mathjax3_config'] = {
    'chtml': {
        'mtextInheritFont': False,
        'mtextFont': "Lato-Light",
    }
}
template_info['latex_pointsize'] = '11pt'
template_info['latex_fonts']= [
    r'\usepackage[default]{lato}',
    r'\usepackage[scale=.8]{noto-mono}'
    ]
template_info['latex_sphinxsetup'] = [
    # Use black for titles
    'TitleColor={rgb}{0.03,0.01,0.145}',
    # Reduce margins
    'hmargin={1.9cm,1.25cm}',
    'vmargin={3.5cm, 3cm}',
    'marginpar=1.27cm',
    # Format the verbatim blocks
    'verbatimwithframe=true',
    'verbatimsep=3pt',
    'VerbatimBorderColor={rgb}{0.9,0.9,0.9}',
    'verbatimborder=0.5pt',
    'VerbatimColor={rgb}{0.97,0.97,0.97}',
    # format hyperlink color
    'InnerLinkColor={rgb}{0,0.26,0.75}',
    'OuterLinkColor={rgb}{0,0.26,0.75}',
    # format admonitions
    'noteBorderColor={rgb}{0.667,0.667,0.667}',
    'warningBorderColor={rgb}{.75,0.5,0.5}',
    'warningborder=2pt',
    # Use attention admonition for the front page banner
    'attentionBorderColor={rgb}{.8,.8,0}',
    'attentionBgColor={rgb}{1,1,.7}',
    'attentionborder=1pt',
    # Use error admonition for rationale boxes
    'errorBorderColor={rgb}{.5,.75,.5}',
    'errorBgColor={rgb}{.9,.95,.9}',
    'errorborder=1pt',
    # Use hint admonition for comment boxes
    'hintBorderColor={rgb}{.6,.6,.6}',
    'hintBgColor={rgb}{.97,.97,.97}',
    'hintborder=0pt',
    'hintTextColor={rgb}{.4,.4,.4}',
    # Use the normal font for headings
    'HeaderFamily=\\normalfont\\mdseries',
]
template_info['latex_table_style'] = ['booktabs','nocolorrows']
template_info['graphviz_dot_args'] = [
    '-Gfontname=Lato',
    '-Gfontsize=12',
    '-Nfontname=Lato',
    '-Nfontsize=12',
    '-Efontname=Lato',
    '-Efontsize=12'
]

def make_doc_filename(info, id, title, version, status):
    doc_parts = [id.replace(' ',''), title, version]
    status = status.split(' ')[-1].lower()
    if status != 'release':
        doc_parts += [status]
    if all((k in info for k in ('doc_id','quality','issue_no'))):
        return '-'.join(doc_parts)
    return None
template_info['make_filename'] = make_doc_filename

template_info['front_sections'] = [
        'abstract',
        'release-info',
        'todos',
        'license',
        'references',
        'terms',
        'potential-for-change',
        'conventions',
        'pseudocode',
        'assembler',
        'current-status',
        'feedback',
        'inclusive-language',
    ]

if 'author' not in doc_info:
    doc_info['author'] = 'Arm Limited'
doc_info.setdefault('feedback', 'visit :url:`github.com/arm-software/psa-api/issues`' +
                                ' to create a new issue at the PSA Certified API GitHub project')
# force use of Arm copyright notice and OSS license
doc_info['copyright'] = 'Arm Limited and/or its affiliates'
doc_info['license'] = 'arm-psa-certified-api-license'
