// Explicit synthetic local browser fixture, never used by the production app.
import http from 'node:http';
import {readFile} from 'node:fs/promises';
import {resolve,extname} from 'node:path';
const root=resolve('dist-primary-agent');
let state={primary_agent_id:'fixture-offline',primary_connected:false,revision:1,can_set_primary:true,agents:[{id:'fixture-offline',display_name:'Synthetic offline primary',connected:false},{id:'fixture-online',display_name:'Synthetic connected agent',connected:true}]};
const server=http.createServer(async(req,res)=>{
 const send=(code,value)=>{res.writeHead(code,{'Content-Type':'application/json'});res.end(JSON.stringify(value))};
 if(req.url?.startsWith('/api/')){
  if(!req.headers.authorization)return send(403,{});
  if(req.url==='/api/snapshot')return send(200,{local:{host:'Synthetic browser fixture',tasks:[],sessions:[]},team:{availability:{control:true,tasks:true},control:{agents:state.agents},tasks:{tasks:[]}}});
  if(req.url==='/api/primary-agent'){
   if(req.method==='POST'){
    let v;
    try{
     const chunks=[];let bytes=0;
     for await(const c of req){bytes+=c.length;if(bytes>16384)return send(413,{error:'request_too_large'});chunks.push(c)}
     v=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks)));
     if(!v||typeof v!=='object'||Array.isArray(v)||typeof v.agent_id!=='string'||!Number.isSafeInteger(v.revision))return send(400,{error:'invalid_request'});
    }catch{return send(400,{error:'invalid_request'})}
    if(v.revision!==state.revision||!state.agents.some(a=>a.id===v.agent_id&&a.connected))return send(409,{});
    state={...state,primary_agent_id:v.agent_id,primary_connected:true,revision:state.revision+1};
   }
   return send(200,state);
  }
  return send(404,{});
 }
 try{const path=resolve(root,'.'+(req.url==='/'?'/index.html':req.url));if(!path.startsWith(root+'/'))return send(403,{});const bytes=await readFile(path);res.writeHead(200,{'Content-Type':({'.html':'text/html','.js':'text/javascript','.css':'text/css','.woff2':'font/woff2'})[extname(path)]??'application/octet-stream'});res.end(bytes)}catch{send(404,{})}
});
server.listen(18203,'127.0.0.1',()=>console.log('Synthetic primary fixture http://127.0.0.1:18203'));
