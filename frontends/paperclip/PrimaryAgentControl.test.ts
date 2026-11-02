import React from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import {it,expect} from 'vitest';
import {PrimaryAgentControl} from './PrimaryAgentControl';
it('shows loading truth without synthesizing a connected or primary agent',()=>{
 const html=renderToStaticMarkup(React.createElement(PrimaryAgentControl,{capability:'synthetic-test-only'}));
 expect(html).toContain('Loading primary-agent authority');expect(html).toContain('aria-busy="true"');expect(html).toContain('Disconnecting never transfers');expect(html).toContain('Model roles do not promote');expect(html).not.toContain('Ana ajan:');expect(html).not.toContain('Ana ajan yap');
});
