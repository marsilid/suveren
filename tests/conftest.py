import os

# Every check a module produces must be in catalog.py (see suveren.checks.STRICT_IDS).
os.environ["SUVEREN_STRICT_CHECK_IDS"] = "1"
