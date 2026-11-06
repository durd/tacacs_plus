# Sphinx configuration for the API reference, built from the docstrings:
#   pip install -r docs/requirements.txt
#   sphinx-build -W --keep-going docs docs/_build/html
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

with open(os.path.join(ROOT, 'setup.py')) as f:
    release = re.search(r"^version = '(.+)'", f.read(), re.M)[1]
version = release

project = 'tacacs_plus'
author = 'Ryan Petrello, durd'
copyright = 'Ansible by Red Hat and contributors'

extensions = ['sphinx.ext.autodoc', 'sphinx.ext.viewcode', 'sphinx_copybutton', 'sphinx_design']

# copy buttons leave out shell and Python prompts
copybutton_prompt_text = r'\$ |>>> |\.\.\. '
copybutton_prompt_is_regexp = True

# The clients document their constructor arguments in __init__
autoclass_content = 'both'
autodoc_member_order = 'bysource'
autodoc_default_options = {'members': True, 'show-inheritance': True}
# `name` in docstrings means code
default_role = 'literal'

html_theme = 'furo'
html_title = f'tacacs_plus {release}'
exclude_patterns = ['_build']
