"""Existing-owner attachment exercise; provider-side effects are not instrumented."""
import fcntl,json,os,pty,select,struct,subprocess,sys,termios,time
from pathlib import Path
R=Path(__file__).resolve().parents[1]; O=R/'receipts/native-mouse'; sys.path.insert(0,str(O/'capture-libs'))
import pyte
from PIL import Image,ImageDraw,ImageFont
from arvyx_control.cockpit_client import request
from arvyx_control.cockpit_arvyx import frontend_environment
c=json.loads((R/'receipts/live-demo/herdr-native-acceptance.json').read_text()); h=Path(c['owner_home']); f=Path(c['frontend_home']); b=R/'receipts/native-mouse/bin/herdr'; env=frontend_environment(f)
def api(*args): return json.loads(subprocess.check_output([str(b),'--session','amc',*args],env=env))
def snap(): return api('api','snapshot')['result']['snapshot']
before=request(h,'list'); original=snap()['focused_tab_id']; api('tab','focus','w1:t2')
command=[str(O/'open-terminal')]
m,s=pty.openpty(); fcntl.ioctl(s,termios.TIOCSWINSZ,struct.pack('HHHH',34,160,0,0)); p=subprocess.Popen(command,stdin=s,stdout=s,stderr=s,start_new_session=True,env={**os.environ,'PYTHONPATH':''}); os.close(s)
raw=bytearray(); screen=pyte.Screen(160,34); screen.report_device_status=lambda *a,**k: None; stream=pyte.ByteStream(screen)
def drain(t):
 end=time.monotonic()+t
 while time.monotonic()<end:
  if select.select([m],[],[],.05)[0]:
   try: data=os.read(m,262144); raw.extend(data); stream.feed(data)
   except OSError: break

def capture(name):
 (O/(name+'.txt')).write_text('\n'.join(screen.display)+'\n')
 font=ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf',14)
 image=Image.new('RGB',(160*9,34*18),(24,25,30)); draw=ImageDraw.Draw(image)
 for y,line in enumerate(screen.display): draw.text((0,y*18),line,font=font,fill=(220,220,230))
 image.save(O/(name+'.png'))

def click(x,y): os.write(m,f'\x1b[<0;{x};{y}M\x1b[<0;{x};{y}m'.encode()); drain(.7)
try:
 drain(3); capture('entry')
 assert 'Hermes sessions' in '\n'.join(screen.display),'not native mouse entry'
 assert 'Select agent' not in raw.decode(errors='replace'),'textual gate returned'
 click(34,34) # All
 os.write(m,b'nova-native'); drain(.7); capture('search')
 assert c['conversation'] in '\n'.join(screen.display)
 click(45,7) # exact bound native session row
 state=snap(); assert state['focused_pane_id']=='w1:p1',state
 capture('selected')
 # The existing native agent rail (not a textual gate) opens the chooser.
 click(10,21); capture('agent-rail-chooser')
 assert 'Search title / exact ID:' in '\n'.join(screen.display)
 assert '● nova-native' in '\n'.join(screen.display)
 # Existing native tabs remain mouse-selectable and are not replaced.
 click(49,1); assert snap()['focused_tab_id']=='w1:t2'
 click(10,21); click(45,7); assert snap()['focused_pane_id']=='w1:p1'
 click(45,34); assert snap()['focused_pane_id']=='w1:p1' # disabled New
 click(24,34); click(34,34) # Last 5, All
 os.write(m,b'\x1b[<65;70;10M\x1b[<64;70;10M'); drain(.4)
 capture('selected-chooser')
 click(74,34); drain(.5); assert p.wait(timeout=5)==0
 after=request(h,'list'); assert [(r['id'],r['pid'],r['status']) for r in before]==[(r['id'],r['pid'],r['status']) for r in after]
 (O/'installed-native-mouse.raw').write_bytes(raw)
 receipt={'command':command,'exact_conversation':c['conversation'],'selected_pane':state['focused_pane_id'],'installed_entry':True,'mouse_selection':True,'native_agent_rail_opens_chooser':True,'native_tabs_preserved':True,'disabled_new_no_launch':None,'last5_and_all_clicks':True,'wheel_events_exercised':True,'search_consumed_by_client':None,'typed_provider_input':None,'fresh_startup_invoked':None,'auth_resolver_invoked':None,'detach_preserved_ids_pids_status':True,'limitations':['Only one existing bound Hermes native conversation; multi-agent and >5 live-session traversal not demonstrated.','Last 5 refers to existing bound sessions, not cold native history.']}
 # Focus/session preservation does not observe provider input or process creation.

 receipt['unmeasured']=['Provider input, fresh native startup and auth-resolver invocation were not instrumented.']
 (O/'acceptance.json').write_text(json.dumps(receipt,indent=2)+'\n'); print(json.dumps(receipt,indent=2))
finally:
 (O/'installed-native-mouse.raw').write_bytes(raw)
 if p.poll() is None: p.terminate(); p.wait(timeout=5)
 os.close(m)
 api('tab','focus',original)
