#!/bin/bash
# KLTN benign — profile "dev" (kltn-dev). Normal software work: git, python venv, a tiny build + tests.
set -u
H="$HOME"; R="$H/project"; LOG="$H/.dev.log"
export GIT_AUTHOR_NAME=kltn-dev GIT_AUTHOR_EMAIL=dev@kltn.lab GIT_COMMITTER_NAME=kltn-dev GIT_COMMITTER_EMAIL=dev@kltn.lab
if [ ! -d "$R/.git" ]; then mkdir -p "$R"; cd "$R" || exit 0; git init -q; echo "# project" > README.md; git add -A; git commit -q -m init 2>/dev/null; fi
cd "$R" || exit 0
pick(){ echo $((RANDOM % $1)); }
case $(pick 6) in
 0) f="mod_$((RANDOM%6)).py"; echo "def f$RANDOM(): return $RANDOM" >> "$f"; git add -A; git commit -q -m "edit $f" 2>/dev/null; git log --oneline -n 5 >/dev/null ;;
 1) git status >/dev/null; git diff >/dev/null; git log --stat -n 3 >/dev/null 2>&1 ;;
 2) if [ ! -d "$R/.venv" ]; then python3 -m venv "$R/.venv" 2>/dev/null; fi; "$R/.venv/bin/pip" -q install --disable-pip-version-check requests 2>>"$LOG" || true ;;
 3) printf 'import sys\nprint(sum(range(1000)))\n' > run.py; python3 run.py >/dev/null ;;
 4) printf '#include <stdio.h>\nint main(){int s=0;for(int i=0;i<100;i++)s+=i;printf("%%d\\n",s);return 0;}\n' > calc.c; if command -v gcc >/dev/null; then gcc calc.c -o calc 2>/dev/null && ./calc >/dev/null; fi ;;
 5) printf 'def test_ok():\n    assert 1+1==2\n' > test_x.py; if "$R/.venv/bin/python" -c "import pytest" 2>/dev/null; then "$R/.venv/bin/python" -m pytest -q >/dev/null 2>&1; else python3 -c "assert 1+1==2"; fi ;;
esac
