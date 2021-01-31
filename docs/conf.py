# -*- coding: utf-8 -*-
"""
Configuration file for the Sphinx documentation builder.

For a full list of options see the documentation:
http://www.sphinx-doc.org/en/master/config
"""

import os
import sys

sys.path.insert(0, os.path.abspath('../src'))

from importlib import import_module

import version  # noqa:E402


# -- Project information -----------------------------------------------------

project = u'PyBitmessage'
copyright = u'2019-2022, The Bitmessage Team'  # pylint: disable=redefined-builtin
author = u'The Bitmessage Team'

# The short X.Y version
version = unicode(version.softwareVersion)

# The full version, including alpha/beta/rc tags
release = version

# -- General configuration ---------------------------------------------------

# If your documentation needs a minimal Sphinx version, state it here.
#
# needs_sphinx = '1.0'

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.coverage',  # FIXME: unused
    'sphinx.ext.imgmath',  # legacy unused
    'sphinx.ext.intersphinx',
    'sphinx.ext.linkcode',
    'sphinx.ext.napoleon',
    'sphinx.ext.todo',
    'sphinxcontrib.apidoc',
    'm2r',
]

default_role = 'obj'

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

# The suffix(es) of source filenames.
# You can specify multiple suffix as a list of string:
#
source_suffix = ['.rst', '.md']

# The master toctree document.
master_doc = 'index'

# The language for content autogenerated by Sphinx. Refer to documentation
# for a list of supported languages.
#
# This is also used if you do content translation via gettext catalogs.
# Usually you set "language" from the command line for these cases.
# language = None

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path .
exclude_patterns = ['_build']

# The name of the Pygments (syntax highlighting) style to use.
pygments_style = 'sphinx'

# Don't prepend every class or function name with full module path
add_module_names = False

# A list of ignored prefixes for module index sorting.
modindex_common_prefix = ['pybitmessage.']


# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = 'sphinx_rtd_theme'

# Theme options are theme-specific and customize the look and feel of a theme
# further.  For a list of options available for each theme, see the
# documentation.
#
# html_theme_options = {}

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ['_static']

html_css_files = [
    'custom.css',
]

# Custom sidebar templates, must be a dictionary that maps document names
# to template names.
#
# The default sidebars (for documents that don't match any pattern) are
# defined by theme itself.  Builtin themes are using these templates by
# default: ``['localtoc.html', 'relations.html', 'sourcelink.html',
# 'searchbox.html']``.
#
# html_sidebars = {}

html_show_sourcelink = False

# -- Options for HTMLHelp output ---------------------------------------------

# Output file base name for HTML help builder.
htmlhelp_basename = 'PyBitmessagedoc'


# -- Options for LaTeX output ------------------------------------------------

latex_elements = {
    # The paper size ('letterpaper' or 'a4paper').
    #
    # 'papersize': 'letterpaper',

    # The font size ('10pt', '11pt' or '12pt').
    #
    # 'pointsize': '10pt',

    # Additional stuff for the LaTeX preamble.
    #
    # 'preamble': '',

    # Latex figure (float) alignment
    #
    # 'figure_align': 'htbp',
}

# Grouping the document tree into LaTeX files. List of tuples
# (source start file, target name, title,
#  author, documentclass [howto, manual, or own class]).
latex_documents = [
    (master_doc, 'PyBitmessage.tex', u'PyBitmessage Documentation',
     u'The Bitmessage Team', 'manual'),
]


# -- Options for manual page output ------------------------------------------

# One entry per manual page. List of tuples
# (source start file, name, description, authors, manual section).
man_pages = [
    (master_doc, 'pybitmessage', u'PyBitmessage Documentation',
     [author], 1)
]


# -- Options for Texinfo output ----------------------------------------------

# Grouping the document tree into Texinfo files. List of tuples
# (source start file, target name, title, author,
#  dir menu entry, description, category)
texinfo_documents = [
    (master_doc, 'PyBitmessage', u'PyBitmessage Documentation',
     author, 'PyBitmessage', 'One line description of project.',
     'Miscellaneous'),
]


# -- Options for Epub output -------------------------------------------------

# Bibliographic Dublin Core info.
epub_title = project
epub_author = author
epub_publisher = author
epub_copyright = copyright

# The unique identifier of the text. This can be a ISBN number
# or the project homepage.
#
# epub_identifier = ''

# A unique identification for the text.
#
# epub_uid = ''

# A list of files that should not be packed into the epub file.
epub_exclude_files = ['search.html']


# -- Extension configuration -------------------------------------------------

autodoc_mock_imports = [
    'debug',
    'pybitmessage.bitmessagekivy',
    'pybitmessage.bitmessageqt.foldertree',
    'pybitmessage.helper_startup',
    'pybitmessage.mock',
    'pybitmessage.network.httpd',
    'pybitmessage.network.https',
    'ctypes',
    'dialog',
    'gi',
    'kivy',
    'logging',
    'msgpack',
    'numpy',
    'pkg_resources',
    'pycanberra',
    'pyopencl',
    'PyQt4',
    'PyQt5',
    'qrcode',
    'stem',
    'xdg',
]
autodoc_member_order = 'bysource'

# Apidoc settings
apidoc_module_dir = '../pybitmessage'
apidoc_output_dir = 'autodoc'
apidoc_excluded_paths = [
    'bitmessagekivy', 'build_osx.py',
    'bitmessageqt/addressvalidator.py', 'bitmessageqt/foldertree.py',
    'bitmessageqt/migrationwizard.py', 'bitmessageqt/newaddresswizard.py',
    'helper_startup.py',
    'kivymd', 'mock', 'main.py', 'navigationdrawer', 'network/http*',
    'src', 'tests', 'version.py'
]
apidoc_module_first = True
apidoc_separate_modules = True
apidoc_toc_file = False
apidoc_extra_args = ['-a']

# Napoleon settings
napoleon_google_docstring = True


# linkcode function
def linkcode_resolve(domain, info):
    """This generates source URL's for sphinx.ext.linkcode"""
    if domain != 'py' or not info['module']:
        return
    try:
        home = os.path.abspath(import_module('pybitmessage').__path__[0])
        mod = import_module(info['module']).__file__
    except ImportError:
        return
    repo = 'https://github.com/Bitmessage/PyBitmessage/blob/v0.6/src%s'
    path = mod.replace(home, '')
    if path != mod:
        # put the link only for top level definitions
        if len(info['fullname'].split('.')) > 1:
            return
        if path.endswith('.pyc'):
            path = path[:-1]
        return repo % path


# -- Options for intersphinx extension ---------------------------------------

# Example configuration for intersphinx: refer to the Python standard library.
intersphinx_mapping = {'https://docs.python.org/2.7/': None}

# -- Options for todo extension ----------------------------------------------

# If true, `todo` and `todoList` produce output, else they produce nothing.
todo_include_todos = True
