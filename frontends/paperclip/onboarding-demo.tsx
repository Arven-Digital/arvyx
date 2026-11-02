import React from 'react';
import {createRoot} from 'react-dom/client';
import {PublicOnboarding} from './PublicOnboarding';
import {SYNTHETIC_DEMO_CAPABILITY} from './workspace-request';
import './style.css';
fetch('/fixture-session',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:'{}'}).then(r=>{if(!r.ok)throw Error('Private fixture session unavailable');createRoot(document.getElementById('root')!).render(<PublicOnboarding capability={SYNTHETIC_DEMO_CAPABILITY}/>)}).catch(()=>{document.body.textContent='Fixture session unavailable. No actions enabled.'});
