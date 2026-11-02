// AMC statuses remain visible verbatim; Paperclip lanes are presentation only.
export function validateSnapshot(snapshot:any){
 const object=(v:any)=>v!==null&&typeof v==='object'&&!Array.isArray(v);
 if(!object(snapshot)||!object(snapshot.local)||!object(snapshot.team)||!object(snapshot.team.availability)
  ||Object.values(snapshot.team.availability).some(v=>typeof v!=='boolean')
  ||snapshot.local.tasks!==undefined&&!Array.isArray(snapshot.local.tasks)
  ||snapshot.local.sessions!==undefined&&!Array.isArray(snapshot.local.sessions)
  ||snapshot.team.availability.tasks===true&&(!object(snapshot.team.tasks)||!Array.isArray(snapshot.team.tasks.tasks))
  ||snapshot.team.availability.control===true&&(!object(snapshot.team.control)||!Array.isArray(snapshot.team.control.agents)))throw Error('Invalid workspace snapshot. Authority unavailable.');
 const tasks=snapshot.team.availability.tasks===true?snapshot.team.tasks.tasks:snapshot.local.tasks??[];
 const agents=snapshot.team.control?.agents??[];
 if(!Array.isArray(agents)||agents.some((a:any)=>!object(a)||typeof a.id!=='string'||!a.id)
  ||tasks.some((t:any)=>!object(t)||typeof t.id!=='string'||!t.id||typeof t.title!=='string'||typeof t.status!=='string')
  ||(snapshot.local.sessions??[]).some((s:any)=>!object(s)))throw Error('Invalid workspace snapshot. Authority unavailable.');
 return snapshot;
}
export function adapt(snapshot:any){
 validateSnapshot(snapshot);
 const team=snapshot.team;
 const tasks=team.availability?.tasks ? team.tasks.tasks : snapshot.local.tasks??[];
 const sessions=snapshot.local.sessions??[];
 const status:Record<string,string>={pending:'todo',open:'todo',active:'in_progress',running:'in_progress',review:'in_review',completed:'done',done:'done',blocked:'blocked',retired:'cancelled',cancelled:'cancelled',backlog:'backlog',in_progress:'in_progress'};
 return {agents:team.control?.agents??[],sessions,issues:tasks.map((t:any)=>({ ...t,identifier:t.id,rawStatus:t.status,status:status[t.status]??'backlog',priority:'none',assigneeAgentId:t.owner??null,projectId:sessions.find((s:any)=>s.task===t.id)?.project??null,labels:[],createdAt:t.created_at??null,updatedAt:t.updated_at??null,parentId:null }))};
}
