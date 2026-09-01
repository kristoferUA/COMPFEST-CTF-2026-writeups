#!/usr/bin/env python3
import argparse
import re
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from solve import decode_archive

parser = argparse.ArgumentParser(description="Decode BurhanQuest sealed archive hex with recovered ops")
parser.add_argument("hex")
parser.add_argument("ops", help="Python-style list, e.g. '[11, 9, 10, 8, 0, 12, 16, 14, 6]'")
args = parser.parse_args()
ops = [int(x) for x in re.findall(r"\d+", args.ops)]
print(decode_archive(args.hex, ops))
