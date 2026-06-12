import json, os, sys, hashlib, argparse, re, subprocess
from datetime import datetime, timezone
from pathlib import Path

IS_EXCLUDED = lambda p: any(s in p.replace(chr(92),chr(47)).split(chr(47)) for s in [chr(110)+chr(111)+chr(100)+chr(101)+chr(95)+chr(109)+chr(111)+chr(100)+chr(117)+chr(108)+chr(101)+chr(115), chr(77)+chr(105)+chr(103)+chr(114)+chr(97)+chr(116)+chr(105)+chr(111)+chr(110)+chr(115)])

print(IS_EXCLUDED(chr(115)+chr(114)+chr(99)+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(47)+chr(102)+chr(111)+chr(111)))
print(chr(39) + 'OK' + chr(39))
