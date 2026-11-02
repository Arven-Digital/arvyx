// Local HTTP edge and deterministic SYNTHETIC fixtures. No production connection.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import {createRequire} from 'node:module';
import {execFileSync} from 'node:child_process';
const require = createRequire(import.meta.url);
const {chromium} = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const out = process.env.EVIDENCE_DIR || '/tmp/amc-dashboard-evidence';
fs.mkdirSync(out, {recursive:true});
const baseline = process.env.BASELINE === '1';
const html = baseline ? execFileSync('git',['show','f45cadb13aa3e0e15e9a8a9addc303ccd10e7794:packages/arvctl/src/arvyx_control/static/index.html'],{encoding:'utf8'}) : fs.readFileSync(new URL('../src/arvyx_control/static/index.html', import.meta.url), 'utf8');
const stamp = '2026-09-22T09:00:00Z';
const agents = ['sage','juniper','keeper','harbor','kedik'].map((id,i)=>({id,display_name:id[0].toUpperCase()+id.slice(1),dashboard:{desk:null,hidden:false,squad:id!=='kedik'},runtime:{id:'hermes-'+id},machine:'SYNTHETIC office',scopes:['control.read','control.write','control.delivery','memory.read','memory.suggest','session.read','session.write'],presence:{state:'registered',heartbeat_at:null},work:{current:7,queued:2,active:5,review:0,done:310},blockers:{count:i===0?5:0},continuation:{state:'stale',active_count:5,stale_count:5,oldest_progress_age_seconds:1728000,subjects:[{id:'SYNTHETIC-long-continuation-identifier-'.repeat(4)}]}}));
const events = [...Array.from({length:9},(_,i)=>({id:'tick-'+i,type:i%2?'execution.watchdog.tick':'outbox.dispatcher.tick',timestamp:stamp})),{id:'work-1',type:'control.thread.post',title:'SYNTHETIC blocker needs operator review',actor:'sage',target:'operator',timestamp:stamp}];
const model = {generated_at:stamp,agents,events,kanban:{queued:[{id:'synthetic-squad',owner:'sage',title:'SYNTHETIC squad work'},{id:'synthetic-other',owner:'outside-squad',title:'SYNTHETIC other work'}],active:[],review:[],done:[]},fleet:{verdict:'red',red:['held_executions','delivery_attention','acked_without_live_execution'],amber:['leased_without_recent_heartbeat','stale_continuations','held_executions'],execution:{held_count:2},watchdog:{initialized:false}},delivery:{ok:false,attention:['ambiguous_delivery'],counts:{total:4},dispatcher:{initialized:false}},source:{bounds:{events_returned:10,events_truncated:true}}};
const summary = {mcp_profile:'SYNTHETIC local regression',recent:{threads:[{id:'thread-synthetic',title:'SYNTHETIC investigate blocked work',actor:'sage',target:'operator',pending:true,severity:'blocker'},{id:'thread-synthetic-retired',title:'SYNTHETIC preserved retired alert',actor:'sage',target:'operator',pending:false,status:'retired'}],approvals:[],handoffs:[]}};
let mode='disabled', readFailure=false, auditBroken=false; const requests=[];
const server = http.createServer(async(req,res)=>{
 let raw=''; for await (const c of req) raw+=c;
 requests.push({url:req.url,method:req.method,headers:req.headers});
 const json=(status,body)=>{res.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(JSON.stringify(body));};
 if(req.url==='/'){res.writeHead(200,{'Content-Type':'text/html'});res.end(html.replace('<main id="main">','<main id="main"><p style="padding:12px;border:2px solid #ffbd59">SYNTHETIC LOCAL REGRESSION — not production data</p>'));return;}
 if(req.url.startsWith('/secret-delivery/')){
  if(mode==='disabled')return json(503,{error:'secret-delivery-disabled'});
  if(mode==='unauthorized')return json(403,{error:'denied'});
  if(req.url.endsWith('/bootstrap'))return json(200,{csrf:'SYNTHETIC-CSRF',targets:mode==='empty'?[]:[{id:'synthetic-sage',agent:'sage',runtime:'synthetic',allowed_keys:['SYNTHETIC_KEY']}]});
  if(req.headers['x-secret-csrf']!=='SYNTHETIC-CSRF')return json(403,{error:'denied'});
  if(req.url.endsWith('/prepare'))return json(200,{exists:false,confirmation:'SYNTHETIC-CONFIRMATION'});
  return json(200,{receipt:{delivery_id:'synthetic-receipt',status:'ambiguous',target:'synthetic-sage',key:'SYNTHETIC_KEY'}});
 }
 if(req.url==='/control-plane')return json(readFailure?503:200,{body:readFailure?{error:'SYNTHETIC read failure'}:model});
 if(req.url.startsWith('/summary'))return json(200,{body:summary});
 if(req.url.startsWith('/audit/events'))return json(200,{body:{chain:{ok:!auditBroken},total:10}});
 if(req.url.startsWith('/executions'))return json(200,{body:{executions:[{id:'synthetic-held',target:'sage',status:'held',subject_id:'SYNTHETIC blocked work'}],events:[{id:'synthetic-held-event',type:'execution.held',reason:'SYNTHETIC approval missing',timestamp:stamp}]}});
 json(404,{error:'SYNTHETIC unknown route'});
});
await new Promise(r=>server.listen(0,'127.0.0.1',r));
const browser=await chromium.launch({headless:true, ...(process.env.CHROMIUM_EXECUTABLE ? {executablePath:process.env.CHROMIUM_EXECUTABLE} : {})});
const errors=[]; const results=[];
const coverageFailures=[];
async function checkCoverage(page,width) {
 const cases=await page.evaluate(()=>{
  const saved=model, savedSelection=selectedAgent;
  // Fleet membership is the registry hint dashboard.squad, never a named list.
  const squad=saved.agents.filter(a=>a.dashboard?.squad===true);
  const changed=(value)=>squad.map((a,i)=>i? a:{...a,continuation:{stale_count:value}});
  const fixtures=[
   ['missing-agents',undefined,false], ['only-juniper',squad.filter(a=>a.id==='juniper'),true],
   ['all-four-valid',squad,true], ['one-count-missing',changed(undefined),false],
   ['duplicate-hides-missing',[squad[0],squad[0],squad[1],squad[2]],false],
   ['duplicate-extra',[...squad,squad[0]],false],
   ['unknown-ignored',[...squad,{id:'unknown',continuation:{stale_count:999}}],true],
   ['unknown-not-fleet',[...squad.slice(0,3),{id:'unknown',continuation:{stale_count:0}}],true],
   ['negative',changed(-1),false], ['boolean',changed(true),false],
   ['fraction',changed(0.5),false], ['string',changed('5'),false],
   ['all-zero',squad.map(a=>({...a,continuation:{stale_count:0}})),true],
  ];
  try { return fixtures.map(([name,records,complete])=>{
   selectedAgent=null;model={...saved,agents:records,kanban:{...saved.kanban,active:[{owner:'sage'},{owner:'unknown'}]}};
   renderAll();
   const fleet=new Set((records||[]).filter(a=>a.dashboard?.squad===true).map(a=>a.id));
   const total=(records||[]).filter(a=>fleet.has(a.id)).reduce((t,a)=>t+(Number.isInteger(a.continuation?.stale_count)?a.continuation.stale_count:0),0);
   return {name,complete,total,sageInFleet:fleet.has('sage'),queued:document.querySelector('#metric-queued strong').textContent,active:document.querySelector('#metric-active strong').textContent,backlog:document.querySelector('#triage-backlog').textContent,fleet:document.querySelector('#metric-fleet').textContent};
  }); } finally {model=saved;selectedAgent=savedSelection;renderAll();}
 });
 for(const row of cases){
  try {
   const owned=row.sageInFleet?'1':'0'; assert.equal(row.queued,owned);assert.equal(row.active,owned);
   assert.match(row.fleet,/Red · 3 critical/);
   if(row.complete) assert.ok(row.backlog.includes(`${row.total} stale continuation records · configured fleet`));
   else {assert.match(row.backlog,/incomplete \/ not reported/);assert.doesNotMatch(row.backlog,/\d+ stale continuation records · configured fleet/);}
  }catch(error){coverageFailures.push({width,case:row.name,error:String(error),actual:row});}
 }
 fs.writeFileSync(path.join(out,`coverage-${width}.json`),JSON.stringify(cases,null,2));
}
try {
 for(const width of [1280,1440,390]){
  const page=await browser.newPage({viewport:{width,height:900},reducedMotion:'reduce'});
  page.on('pageerror',e=>errors.push(String(e)));
  await page.goto(`http://127.0.0.1:${server.address().port}`);
  await page.waitForFunction(()=>document.querySelectorAll('.agent-desk').length===4);
  await page.evaluate(()=>scrollTo(0,0));
  await page.screenshot({path:path.join(out,`${baseline?'before':'after'}-${width}.png`),fullPage:true});
  const roomBounds=await page.locator('.hq-layout').boundingBox();
  fs.writeFileSync(path.join(out,`${baseline?'before':'after'}-war-room-${width}-bounds.json`),JSON.stringify(roomBounds));
  if(!baseline){
   await checkCoverage(page,width);
   if(process.env.COVERAGE_ONLY==='1'){await page.close();continue;}
   assert.deepEqual((await page.locator('.desk-name').allTextContents()).sort(),['Harbor','Juniper','Keeper','Sage']);
   assert.equal(await page.locator('#attention-actions .cause-card').count(),4);
   assert.match(await page.locator('#metric-fleet').innerText(),/Fleet verdict · global[\s\S]*Red · 3 critical/i);
   assert.equal(await page.locator('#metric-queued strong').innerText(),'1');
   assert.match(await page.locator('#triage-backlog').innerText(),/20 stale continuation records · configured fleet/);
   assert.match(await page.locator('#triage-backlog').innerText(),/2 held execution records · global/);
   const codes = await page.locator('#triage-source').innerText();
   for(const code of new Set([...model.fleet.red,...model.fleet.amber,...model.delivery.attention])) assert.equal(codes.split(code).length-1,1);
   assert.equal(await page.locator('#triage-runtime a').count(),4);
   await page.getByRole('link',{name:'Sage: 5 blockers → threads',exact:true}).click();
   assert.match(await page.locator('#threads').innerText(),/SYNTHETIC investigate/);
   assert.match(await page.locator('#threads').innerText(),/thread-synthetic-retired · retired · not completed/i);
   assert.match(await page.locator('#triage-decisions').innerText(),/1 pending operator thread records/);
   assert.doesNotMatch(await page.locator('#recently-completed').innerText(),/retired alert/);
   assert.match(await page.locator('#metric-fleet').innerText(),/Red · 3 critical/);
   await page.locator('#clear-filter').click();
   assert.ok(!(await page.locator('#live-signal').innerText()).includes('.tick'));
   assert.ok((await page.locator('#live-signal').innerText()).includes('SYNTHETIC blocker'));
   await page.getByText('Operational events · dispatcher / watchdog', {exact:true}).click();
   assert.ok((await page.locator('#operational-events').innerText()).includes('.tick'));
   await page.getByText('Operational events · dispatcher / watchdog', {exact:true}).click();
   assert.ok((await page.locator('#agent-detail').innerText()).includes('Runtime status unknown'));
   const geometry=await page.evaluate(()=>({pageOverflow:document.documentElement.scrollWidth>innerWidth,detailOverflow:document.querySelector('#agent-detail').scrollWidth>document.querySelector('#agent-detail').clientWidth,detailScroll:getComputedStyle(document.querySelector('#agent-detail')).overflowY,metricRows:[...document.querySelectorAll('.metric')].map(x=>x.getBoundingClientRect().top)}));
   assert.equal(geometry.pageOverflow,false,JSON.stringify(geometry));assert.equal(geometry.detailOverflow,false);assert.equal(geometry.detailScroll,'visible');
   if(width>1000)assert.equal(new Set(geometry.metricRows).size,2);
   await page.getByRole('button',{name:'Inspect Juniper',exact:true}).click();
   assert.match(await page.locator('#agent-detail').innerText(),/Juniper/);
   await page.locator('#clear-filter').click();
   await page.getByRole('link',{name:'Inspect held execution evidence →'}).click();
   await page.waitForSelector('.execution-row');
   assert.match(await page.locator('#workbench-executions').innerText(),/1 held records in returned execution list · global/);
   assert.equal(await page.getByRole('button',{name:'Show all returned executions',exact:true}).count(),1);
   await page.locator('.execution-row').click();
   await page.waitForFunction(()=>document.querySelector('#workbench-events').textContent.includes('SYNTHETIC approval missing'));
   assert.equal(await page.locator('#workbench-resume').isDisabled(),true);
   await page.locator('#view-observatory').click();
   await page.locator('#secret-connect').click();await page.waitForFunction(()=>document.querySelector('#secret-receipt').textContent.includes('not configured'));
   assert.equal(await page.locator('#secret-send').isDisabled(),true);
   mode='unauthorized';await page.locator('#secret-connect').click();await page.waitForFunction(()=>document.querySelector('#secret-receipt').textContent.includes('not authorized'));
   mode='empty';await page.locator('#secret-connect').click();await page.waitForFunction(()=>document.querySelector('#secret-receipt').textContent.includes('No destinations'));
   assert.equal(await page.locator('#secret-send').isDisabled(),true);
   mode='ready';await page.locator('#secret-connect').click();await page.waitForFunction(()=>!document.querySelector('#secret-send').disabled);
   await page.locator('#secret-name').fill('SYNTHETIC_KEY');await page.locator('#secret-value').fill('SYNTHETIC-NOT-A-CREDENTIAL');
   await page.locator('#secret-send').click();await page.waitForFunction(()=>document.querySelector('#secret-receipt').textContent.includes('ambiguous'));
   assert.equal(await page.locator('#secret-send').isDisabled(),true);assert.equal(await page.locator('#secret-value').inputValue(),'');
   await page.locator('#secret-status-check').click();
   await page.locator('#open-drawer').click();
   await page.waitForFunction(()=>document.querySelector('#drawer').classList.contains('open'));
   await page.keyboard.press('Shift+Tab');
   assert.equal(await page.evaluate(()=>document.querySelector('#drawer').contains(document.activeElement)),true);
   await page.keyboard.press('Escape');
   await page.waitForFunction(()=>document.querySelector('#drawer').hidden && document.querySelector('#backdrop').hidden);
   assert.equal(await page.locator('#open-drawer').evaluate(n=>n===document.activeElement),true);
   const savedFleet=model.fleet,savedDelivery=model.delivery;delete model.fleet;delete model.delivery;
   await page.locator('#refresh-all').click();await page.waitForFunction(()=>document.querySelector('#freshness-label').textContent.includes('status unknown'));
   assert.match(await page.locator('#metric-delivery').innerText(),/Not reported/);
   await page.screenshot({path:path.join(out,`unknown-${width}.png`)});
   model.fleet=savedFleet;model.delivery=savedDelivery; auditBroken=true;
   await page.locator('#refresh-all').click();await page.waitForFunction(()=>document.querySelector('#posture').textContent.includes('BROKEN'));
   auditBroken=false;readFailure=true;
   await page.locator('#refresh-all').click();await page.waitForFunction(()=>document.querySelector('#state-banner').textContent.includes('Showing last successful snapshot'));
   assert.equal(await page.locator('.agent-desk').count(),4);
   assert.match(await page.locator('#triage-runtime').innerText(),/Runtime availability · unknown/);
   await page.screenshot({path:path.join(out,`read-failure-${width}.png`)});
   readFailure=false;
   await page.context().setOffline(true);
   await page.locator('#refresh-all').click();
   await page.waitForFunction(()=>!inFlight && document.querySelector('#freshness-label').textContent==='Signal unavailable');
   assert.match(await page.locator('#triage-runtime').innerText(),/Runtime availability · unknown/);
   assert.match(await page.locator('#state-banner').innerText(),/Showing last successful snapshot/);
   await page.screenshot({path:path.join(out,`offline-${width}.png`)});
   await page.context().setOffline(false);
   const savedAgents=model.agents, savedKanban=model.kanban, savedRecent=summary.recent;
   model.agents=[];model.kanban={queued:[],active:[],review:[],done:[]};summary.recent={threads:[],approvals:[]};
   await page.locator('#refresh-all').click();await page.waitForFunction(()=>document.querySelectorAll('.agent-desk').length===0);
   assert.equal(await page.locator('#metric-queued strong').innerText(),'0');
   assert.match(await page.locator('#triage-runtime').innerText(),/No squad records returned; availability remains unknown/);
   assert.match(await page.locator('#triage-decisions').innerText(),/0 requested approval records/);
   await page.screenshot({path:path.join(out,`empty-${width}.png`)});
   delete model.kanban;delete summary.recent;
   await page.locator('#refresh-all').click();await page.waitForFunction(()=>document.querySelector('#triage-decisions').textContent.includes('not reported'));
   assert.equal(await page.locator('#metric-queued strong').innerText(),'Not reported');
   assert.match(await page.locator('#triage-backlog').innerText(),/incomplete \/ not reported/);
   model.agents=savedAgents;model.kanban=savedKanban;summary.recent=savedRecent;
   results.push({width,geometry,checks:'fleet, signal split, runtime unknown, overflow, held cause link, held controls fail closed, Access states, CSRF, ambiguity, focus containment/return, missing telemetry, broken audit, stale snapshot'});
   mode='disabled';
  }
  await page.close();
 }
 fs.writeFileSync(path.join(out,'coverage-failures.json'),JSON.stringify(coverageFailures,null,2));
 assert.deepEqual(coverageFailures,[]);
 assert.deepEqual(errors,[]);
 if(!baseline && process.env.COVERAGE_ONLY!=='1'){const secret=requests.filter(r=>r.url.startsWith('/secret-delivery/'));assert.ok(secret.every(r=>!r.headers.authorization));assert.ok(secret.filter(r=>!r.url.endsWith('/bootstrap')).every(r=>r.headers['x-secret-csrf']==='SYNTHETIC-CSRF'));}
 fs.writeFileSync(path.join(out,`${baseline?'before':'after'}-results.json`),JSON.stringify({fixture:'SYNTHETIC',baseline:'f45cadb13aa3e0e15e9a8a9addc303ccd10e7794',results,errors},null,2));
 console.log(JSON.stringify({status:'PASS',baseline,results,evidence:out}));
} finally {await browser.close();server.close();}
