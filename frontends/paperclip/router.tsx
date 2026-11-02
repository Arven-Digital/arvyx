import React from 'react';
import {readRoute,taskRoute} from './navigation';
// Paperclip company routes intentionally terminate in a local AMC detail view.
export function Link({to,children,issuePrefetch,disableIssueQuicklook,...props}:any){return <a {...props} href={taskRoute(String(to).split('/').pop()!,readRoute(location.hash).synthetic)}>{children}</a>}
