// Hash routes stay local; never treat a preview route as an authority capability.
export function readRoute(hash: string): {task: string; synthetic: boolean} {
 const params = new URLSearchParams(hash.replace(/^#/, ''));
 return {task: params.get('task') ?? '', synthetic: params.get('preview') === 'synthetic'};
}
export function taskRoute(task: string, synthetic: boolean): string {
 const params = new URLSearchParams();
 if (synthetic) params.set('preview', 'synthetic');
 if (task) params.set('task', task);
 return '#' + params.toString();
}
