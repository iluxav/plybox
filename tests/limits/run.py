#!/usr/bin/env python3
"""Bounded local integration tests; no API calls, real secrets, or real sessions.
Pass --disk-volume DIR inside a private mount namespace to exercise disk caps.
"""
import concurrent.futures
import http.server
import json
import os
from pathlib import Path
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading

BIN = str(Path(sys.argv[1]).resolve())
VOLUME = Path(sys.argv[3]) if len(sys.argv) > 2 and sys.argv[2] == '--disk-volume' else None
ROOT = Path(__file__).resolve().parents[2]

if VOLUME:
    assert int(next(l.split()[1] for l in open('/proc/self/status') if l.startswith('CapEff:')),16)==0, 'run tests as an ordinary user'
with tempfile.TemporaryDirectory(prefix='plybox-limits-') as t:
    t = Path(t)
    work = t / 'work'; work.mkdir()
    env = {**os.environ, 'XDG_STATE_HOME': str(t/'state')}
    number = 0

    def run(code, *opts, session=None, resume=False, expect=0, program="python3", code_flag="-c"):
        global number
        number += 1
        session = session or t / f'session-{number}'
        argv = [BIN, 'run', '--isolation', 'ns', '--quiet', '--work', str(work),
                '--resume' if resume else '--session', str(session), *opts, '--', program, code_flag, code]
        p = subprocess.run(argv, env=env, text=True, capture_output=True, timeout=20)
        assert p.returncode == expect, (argv, p.returncode, p.stdout, p.stderr)
        events = [json.loads(s) for s in (session/'record.jsonl').read_text().splitlines()] if (session/'record.jsonl').exists() else []
        return session, events

    # Harmless denied ioctls on an invalid fd, and required I/O on a pipe/pty.
    run('''
import os, pty, termios, fcntl, errno, array, subprocess, sys
assert int(next(l.split()[1] for l in open("/proc/self/status") if l.startswith("CapEff:")),16)==0
r,w = os.pipe(); os.write(w,b'hello'); b=array.array('i',[0])
fcntl.ioctl(r,termios.FIONREAD,b); assert b[0]==5
m,s=pty.openpty(); a=termios.tcgetattr(s); termios.tcsetattr(s,termios.TCSANOW,a)
pid,master=os.forkpty()
if pid==0: os._exit(0)
assert os.waitpid(pid,0)[1]==0
os.close(master)
# Python rejects negative descriptors first; libc tests cover those codes.
try: fcntl.ioctl(r,0xdeadbeef,0)
except OSError as e: assert e.errno==errno.ENOSYS
else: raise AssertionError('unlisted ioctl allowed')
child = subprocess.run([sys.executable,'-c','import fcntl; fcntl.ioctl(0,0xdeadbeef,0)'],capture_output=True)
assert child.returncode != 0 and b'Function not implemented' in child.stderr, child.stderr
''')
    print('PASS narrowed ioctl supports Python, pipes and ptys', flush=True)

    s, _ = run('''
import os, resource, errno, signal, subprocess, sys
signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
assert resource.getrlimit(resource.RLIMIT_FSIZE)==(8192,8192)
with open('file','wb',buffering=0) as f:
    f.write(b'x'*8192)
    try: f.write(b'x')
    except OSError as e: assert e.errno==errno.EFBIG
    else: raise AssertionError('file cap missing')
try: os.truncate('file',1000000)
except OSError as e: assert e.errno==errno.EFBIG
else: raise AssertionError('truncate exceeded file cap')
try: resource.setrlimit(resource.RLIMIT_FSIZE,(16384,16384))
except (ValueError,PermissionError): pass
else: raise AssertionError('hard limit raised')
subprocess.run([sys.executable,'-c','import resource; assert resource.getrlimit(resource.RLIMIT_FSIZE)==(8192,8192)'],check=True)
''', '--file-size', '8K')
    run("import resource; assert resource.getrlimit(resource.RLIMIT_FSIZE)==(8192,8192)",session=s,resume=True)
    print('PASS file size, truncate, descendants and saved resume policy', flush=True)

    run('''
import os, errno
for d in ['/tmp','/home/box','/dev/shm']:
    st=os.statvfs(d); assert st.f_blocks*st.f_frsize==1024*1024, (d,st)
    try:
        with open(d+'/fill','wb',buffering=0) as f:
            for _ in range(17): f.write(b'x'*65536)
    except OSError as e: assert e.errno==errno.ENOSPC, (d,e)
    else: raise AssertionError('scratch cap missing: '+d)
    os.unlink(d+'/fill')
for d in ['/dev','/']:
    try: open(d+'/unbounded','wb').close()
    except OSError: pass
    else: raise AssertionError('unbounded writable root: '+d)
''','--tmpfs','3M')
    print('PASS scratch mounts exhaust at their allocated capacity', flush=True)

    for opts in [('--disk','1M'),('--disk','0'),('--tmpfs','1K'),('--bytes-in','18446744073709551615G'),
                 ('--isolation','gvisor','--disk','16M'),('--workspace-mode','bind','--disk','16M')]:
        p = subprocess.run([BIN,'run','--isolation','ns','--work',str(work),*opts,'--','touch','must-not-run'],env=env,capture_output=True,timeout=10)
        assert p.returncode != 0, opts
    assert not (work/'must-not-run').exists()
    print('PASS invalid/unsupported caps refuse execution', flush=True)

    # A bubblewrap without --size (pre-0.9) must be named, not left to fail
    # with bwrap's own "Unknown option". The fake reports 0.8.0 and refuses
    # to run anything, so the check must happen before any launch.
    fake = t / 'oldbwrap'; fake.mkdir()
    (fake/'bwrap').write_text('#!/bin/sh\n[ "$1" = --version ] && echo "bubblewrap 0.8.0" && exit 0\nexit 99\n')
    (fake/'bwrap').chmod(0o755)
    p = subprocess.run([BIN,'run','--isolation','ns','--work',str(work),'--tmpfs','3M','--','touch','must-not-run'],
                       env={**env,'PATH':f"{fake}:{os.environ['PATH']}"},capture_output=True,text=True,timeout=10)
    assert p.returncode != 0 and 'bubblewrap 0.9 or newer' in p.stderr and '0.8.0' in p.stderr, p.stderr
    assert not (work/'must-not-run').exists()
    print('PASS bubblewrap older than 0.9 is refused with a clear message', flush=True)

    # Overlay mounts (the workspace copy, an image root) arrived in 0.11.0;
    # 0.10.0 lacks them (measured in CI). Bind mode on host tools needs none.
    (fake/'bwrap').write_text('#!/bin/sh\n[ "$1" = --version ] && echo "bubblewrap 0.10.0" && exit 0\nexit 99\n')
    old = {**env,'PATH':f"{fake}:{os.environ['PATH']}"}
    p = subprocess.run([BIN,'run','--isolation','ns','--work',str(work),'--','touch','must-not-run'],env=old,capture_output=True,text=True,timeout=10)
    assert p.returncode != 0 and 'bubblewrap 0.11 or newer' in p.stderr and '0.10.0' in p.stderr, p.stderr
    p = subprocess.run([BIN,'run','--isolation','ns','--work',str(work),'--workspace-mode','bind','--','true'],env=old,capture_output=True,text=True,timeout=10)
    assert p.returncode == 99 and 'bubblewrap 0.11' not in p.stderr, (p.returncode, p.stderr)
    assert not (work/'must-not-run').exists()
    print('PASS bubblewrap 0.10 is refused for overlays with a clear message; bind mode still runs', flush=True)

    class Plain(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(5)
            data = bytearray()
            try:
                while not data.endswith(b'\n'):
                    chunk=self.request.recv(2048)
                    if not chunk: break
                    data.extend(chunk)
                with self.server.guard: self.server.received += len(data)
                self.request.sendall(b'r'*65536)
            except OSError: pass
    class Server(socketserver.ThreadingTCPServer):
        daemon_threads = True
        def handle_error(self,*_): pass
    server = Server(('127.0.0.1',0),Plain)
    server.guard=threading.Lock(); server.received=0
    threading.Thread(target=server.serve_forever,daemon=True).start()
    net=['--allow','fixture.test','--map',f'fixture.test=127.0.0.1:{server.server_address[1]}']
    client='''
import socket, concurrent.futures
def once(_):
    s=socket.create_connection(('127.0.0.1',3128),timeout=5)
    try:
        s.sendall(b'CONNECT fixture.test:443 HTTP/1.1\\r\\n\\r\\n')
        h=b''
        while not h.endswith(b'\\r\\n\\r\\n'):
            c=s.recv(1)
            if not c: return
            h+=c
        if b'200' not in h: return
        s.sendall(b'x'*1024+b'\\n')
        while s.recv(4096): pass
    except OSError: pass
    finally: s.close()
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as p: list(p.map(once, range(8)))
'''
    s, events=run(client,*net,'--bytes-out','3000','--bytes-in','5000')
    usage=[e for e in events if e['event']=='net_usage'][-1]
    assert 0<usage['bytes_out']<=3000 and 0<usage['bytes_in']<=5000, usage
    assert any(e['event']=='net_limit' for e in events), events
    assert server.received<=3000, server.received
    _,events=run(client,session=s,resume=True)
    usages=[e for e in events if e['event']=='net_usage']
    assert len(usages)==2 and 0<usages[-1]['bytes_out']<=3000 and usages[-1]['run']==2, usages
    print('PASS concurrent tunnels share budgets; resume starts a fresh budget', flush=True)
    before=server.received
    run(client,*net,'--bytes-out','0')
    assert server.received==before
    server.shutdown(); server.server_close()
    print('PASS zero-byte budget refuses upstream connection', flush=True)

    # TLS termination with a fake key and a locally generated CA. Both the
    # handshake and substituted request pass through the metered transport.
    ca=t/'ca'
    subprocess.run([sys.executable,str(ROOT/'tests/helpers/proxy.py'),'mkcert','--ca-dir',str(ca),'--host','fixture.test'],check=True,capture_output=True)
    seen=[]
    class HTTPS(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.headers.get('x-api-key'))
            self.send_response(200); self.send_header('Content-Length','100000'); self.end_headers()
            try: self.wfile.write(b'r'*100000)
            except OSError: pass
        def log_message(self,*_): pass
    https=http.server.ThreadingHTTPServer(('127.0.0.1',0),HTTPS)
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(ca/'fixture.test.pem'),str(ca/'fixture.test.key'))
    https.socket=ctx.wrap_socket(https.socket,server_side=True)
    threading.Thread(target=https.serve_forever,daemon=True).start()
    tlsnet=['--allow','fixture.test','--map',f'fixture.test=127.0.0.1:{https.server_port}',
            '--trust-ca',str(ca/'ca.pem'),'--secret','TOKEN=fake-test-value@fixture.test']
    tlsclient='''
import os,socket,ssl
s=socket.create_connection(('127.0.0.1',3128),timeout=5)
s.sendall(b'CONNECT fixture.test:443 HTTP/1.1\\r\\n\\r\\n')
h=b''
while not h.endswith(b'\\r\\n\\r\\n'): h+=s.recv(1)
s=ssl.create_default_context().wrap_socket(s,server_hostname='fixture.test',suppress_ragged_eofs=False)
try:
    s.sendall(('GET / HTTP/1.1\\r\\nHost: fixture.test\\r\\nx-api-key: '+os.environ['TOKEN']+'\\r\\n\\r\\n').encode())
    while s.recv(4096): pass
    raise AssertionError('capped TLS response ended cleanly')
except OSError: pass
finally: s.close()
'''
    _,events=run(tlsclient,*tlsnet,'--bytes-in','32K','--bytes-out','16K')
    usage=[e for e in events if e['event']=='net_usage'][-1]
    assert usage['bytes_in']==32768 and 0<usage['bytes_out']<=16384,usage
    assert seen==['fake-test-value'],seen
    _,events=run(tlsclient,*tlsnet,'--bytes-out','100')
    usage=[e for e in events if e['event']=='net_usage'][-1]
    assert usage['bytes_out']==100,usage
    assert len(seen)==1,seen  # handshake capped before HTTP reached the server
    https.shutdown(); https.server_close()
    print('PASS TLS handshake and secret-substituted traffic obey budgets', flush=True)

    if VOLUME:
        s=VOLUME/'saved'
        run('''
import os, errno
with open('keep','w') as f: f.write('saved')
n=0
try:
    for n in range(80):
        with open('fill-'+str(n),'wb',buffering=0) as f: f.write(b'x'*(256*1024))
except OSError as e: assert e.errno==errno.ENOSPC,e
else: raise AssertionError('total disk cap missing')
# Make space for the supervisor's record and session metadata.
for i in range(n+1): os.unlink('fill-'+str(i))
''','--disk','16M',session=s)
        run("assert open('keep').read()=='saved'; open('second','w').write('resumed')",session=s,resume=True)
        assert (s/'upper/second').read_text()=='resumed'
        p=subprocess.run([BIN,'apply',str(s)],env=env,capture_output=True,timeout=10)
        assert p.returncode==0,p.stderr
        assert (work/'keep').read_text()=='saved'
        assert not (s/'upper').exists()
        print('PASS aggregate disk exhaustion, resume, apply and cleanup on a bounded volume', flush=True)

    cached = {line.split()[0] for line in subprocess.check_output([BIN,'images'],text=True).splitlines() if line.strip()}
    image = os.environ.get('PLYBOX_LIMIT_TEST_IMAGE') or ('python:3.13-slim' if 'python:3.13-slim' in cached else None)
    if image:
        run("import os; assert os.statvfs('/tmp').f_blocks*os.statvfs('/tmp').f_frsize==1048576; open('from-image','w').write('ok')",'--image',image,'--tmpfs','3M','--file-size','8K')
        print('PASS bounded scratch and file writes inside '+image, flush=True)
    node_image = os.environ.get('PLYBOX_LIMIT_TEST_NODE_IMAGE') or ('node:22-slim' if 'node:22-slim' in cached else None)
    if node_image:
        run("const fs=require('fs');fs.writeFileSync('node-file','ok');console.log(process.stdout.isTTY);require('child_process').execFileSync('node',['-e','console.log(42)']);",'--image',node_image,'--tmpfs','3M','--file-size','8K',program='node',code_flag='-e')
        print('PASS Node.js image, subprocesses and stdio', flush=True)
    runsc = os.environ.get('PLYBOX_LIMIT_TEST_RUNSC') or (str(ROOT/'tests/tools/runsc') if (ROOT/'tests/tools/runsc').is_file() else None)
    if runsc:
        gs, _ = run("import resource; assert resource.getrlimit(resource.RLIMIT_FSIZE)==(8192,8192); open('/tmp/gvisor-file','w').write('ok')",'--isolation','gvisor','--runsc',runsc,'--file-size','8K')
        # runsc can leave its root bind-mounted when invoked as namespace
        # root. Unmount only this fixture, in the private test namespace.
        if VOLUME:
            # ismount() misses same-filesystem bind mounts.
            while any(line.split()[4] == str(gs/'runsc') for line in Path('/proc/self/mountinfo').read_text().splitlines()):
                subprocess.run(['umount',str(gs/'runsc')],check=True)
        print('PASS gVisor per-file limit and narrowed ioctl startup', flush=True)
