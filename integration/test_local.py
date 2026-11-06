#!/usr/bin/env python3
"""Exécuter les tests locaux sans toucher aux rapports de production."""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from mon_secret_cookie import private_reports
with tempfile.TemporaryDirectory(prefix='prevost-tests-') as directory:
    with patch.object(private_reports, 'directory', return_value=Path(directory)):
        suite = unittest.defaultTestLoader.discover(str(ROOT/'tests'))
        result = unittest.TextTestRunner(verbosity=1).run(suite)
raise SystemExit(not result.wasSuccessful())
