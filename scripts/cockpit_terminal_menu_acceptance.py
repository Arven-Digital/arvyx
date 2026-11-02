"""Real attach-only CLI PTY acceptance: no keystrokes enter a provider prompt."""
import fcntl,json,os,pty,select,struct,subprocess,termios,time
from pathlib import Path
from arvyx_control.cockpit_client import request
from arvyx_control.cockpit_arvyx import frontend_environment
R=Path(__file__).resolve().parents[1]; O=R/'receipts/live-demo'
c=json.loads((O/'herdr-native-acceptance.json').read_text()); h=Path(c['owner_home']); f=Path(c['frontend_home']); b=R/'receipts/frontend/herdr-source/target/release/herdr'; env=frontend_environment(f)
def snap(): return json.loads(subprocess.check_output([str(b),'--session','amc','api','snapshot'],env=env))['result']['snapshot']
before=request(h,'list'); native_before=request(h,'native',sid=c['native_session'],actor='operator')
m,s=pty.openpty(); fcntl.ioctl(s,termios.TIOCSWINSZ,struct.pack('HHHH',34,160,0,0)); p=subprocess.Popen(['/usr/bin/python3',str(R/'scripts/cockpit_terminal_demo.py')],env=dict(os.environ,PYTHONPATH=str(R/'packages/arvctl/src')),stdin=s,stdout=s,stderr=s,start_new_session=True); os.close(s); raw=bytearray()
def drain(t):
 end=time.monotonic()+t
 while time.monotonic()<end:
  if select.select([m],[],[],.05)[0]:
   try: raw.extend(os.read(m,262144))
   except OSError: break
try:
 drain(.3); os.write(m,b'1\n'); drain(.2); os.write(m,b'recent5\n'); drain(.3); os.write(m,b'1\n'); drain(2)
 assert snap()['focused_tab_id']=='w1:t1'
 os.write(m,b'\x1b[<0;51;1M\x1b[<0;51;1m'); drain(.5)
 assert snap()['focused_tab_id']=='w1:t2'
 os.write(m,b'\x1b[<64;80;12M'*3); drain(.5)
 scrolled=next(x for x in snap()['panes'] if x['pane_id']=='w1:p2')['scroll']['offset_from_bottom']
 assert scrolled>0
 os.write(m,b'\x1b[<0;30;1M\x1b[<0;30;1m'); drain(.5)
 assert snap()['focused_tab_id']=='w1:t1'
 (O/'terminal-menu-live.raw').write_bytes(raw)
 os.write(m,b'\x02q'); drain(.5); assert p.wait(timeout=5)==0
 after=request(h,'list'); assert [(r['id'],r['status']) for r in before]==[(r['id'],r['status']) for r in after]
 assert request(h,'native',sid=c['native_session'],actor='operator')==native_before
 receipt={'command':'PYTHONPATH=packages/arvctl/src /usr/bin/python3 scripts/cockpit_terminal_demo.py','cli_agent_selection':True,'recent5_native_exact':c['conversation'],'actual_arvyx':True,'mouse_tab_roundtrip':True,'wheel_offset':scrolled,'detach_exit':p.returncode,'native_binding_preserved':True,'owner_sessions_preserved':True,'provider_input_sent':False,'new_provider_launched':False,'raw_bytes':len(raw)}
 (O/'terminal-menu-live.json').write_text(json.dumps(receipt,indent=2)+'\n'); print(json.dumps(receipt,indent=2))
finally:
 if p.poll() is None: p.terminate(); p.wait(timeout=5)
 os.close(m)
