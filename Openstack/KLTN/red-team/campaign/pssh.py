#!/usr/bin/env python3
# Minimal password-SSH via a pty (stdlib only). Usage: pssh.py user@host "remote command" PASSWORD
import sys, os, pty, select, time
host, cmd, pw = sys.argv[1], sys.argv[2], sys.argv[3]
argv = ["ssh","-o","StrictHostKeyChecking=no","-o","PubkeyAuthentication=no",
        "-o","PreferredAuthentications=keyboard-interactive,password","-o","ConnectTimeout=8", host, cmd]
pid, fd = pty.fork()
if pid == 0:
    os.execvp("ssh", argv)
out = b""; sent = False; deadline = time.time() + 40
while True:
    if time.time() > deadline: break
    r,_,_ = select.select([fd], [], [], 1.0)
    if fd in r:
        try: data = os.read(fd, 4096)
        except OSError: break
        if not data: break
        out += data
        if not sent and (b"assword" in out or b"Password" in out):
            os.write(fd, pw.encode() + b"\n"); sent = True
    try:
        wpid, status = os.waitpid(pid, os.WNOHANG)
        if wpid == pid:
            time.sleep(0.2)
            while True:
                r,_,_ = select.select([fd],[],[],0.3)
                if fd in r:
                    try: d=os.read(fd,4096)
                    except OSError: break
                    if not d: break
                    out += d
                else: break
            rc = os.waitstatus_to_exitcode(status)
            text = out.decode(errors="replace").replace("\r","")
            i = text.find("assword")
            if i != -1:
                nl = text.find("\n", i)
                text = text[nl+1:] if nl != -1 else ""
            sys.stdout.write(text)
            sys.exit(rc if rc is not None else 0)
    except ChildProcessError:
        break
t=out.decode(errors="replace").replace("\r","")
i=t.find("assword")
if i!=-1:
    nl=t.find("\n",i); t=t[nl+1:] if nl!=-1 else ""
sys.stdout.write(t); sys.exit(1)
