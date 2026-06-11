# SPDX-FileCopyrightText: Copyright 2018-2026 Arm Limited
# SPDX-License-Identifier: Apache-2.0

import glob, re

files = []
for f in glob.glob('**/*.html', recursive=True):
   files.append(f)

url_property = r'meta property="og:url" content="{{ site.url }}[^"]*"\s*/>'
url_replace = r'meta property="og:url" content="{{ page.url | absolute_url }}" />\n<link rel="canonical" href="{{ page.url | absolute_url }}" />'

url_re = re.compile(url_property)

for file in files:
   with open(file, encoding='utf-8') as f:
      text = f.read()
   if re.search(url_re, text):
      text = "---\n---\n\n" +re.sub(url_re, url_replace, text)
      print("{}: update for Jekyll processing".format(file))
      with open(file, "w", encoding='utf-8') as f:
         f.write(text)
