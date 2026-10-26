# A deliberately rule-breaking agent module. It lives outside arena/ so it is never imported;
# the import-boundary test scans it to prove each rule is caught.
import importlib
import sqlite3

import arena.judge.process
from arena import db
from arena.judge_client import JudgeClient
from arena.memory import briefing
from arena.memory.memory import _WORD

from ..judge import store

secret = __import__("arena.judge.store")
