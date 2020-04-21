""" application state module
"""
import os
from types import SimpleNamespace

from melddict import MeldDict

from . import log

app = SimpleNamespace(
    # debug
    debug=None,
    # environment variables, these are accessible throughout all plugins
    env=MeldDict(os.environ.copy()),
    # logger
    log=log,
)
