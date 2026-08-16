import os
f = open('C:/temp/omniscience-cyber/rag/shell.py', 'w', encoding='utf-8')
f.write('''#!/usr/bin/env python3
"""
omniscience-shell - Interactive REPL for omniscience-cyber campaigns.
"""

from __future__ import annotations

import argparse
import asyncio
import cmd
import json
import os
import readline
import shlex
import sys
import textwrap
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from .models import Campaign, CampaignStep, CampaignState, StepState, Severity
from .state import CampaignStateStore, CampaignRuntime
from .planner import create_campaign_from_template, get_next_pending_steps, build_context
from .executor import KaliExecutor, ExecutorConfig
from .scope_guard import ScopeGuard
from .findings import create_finding_store
''')
f.close()
print('Part 1 written')