import {defineConfig} from 'vite';
import react from '@vitejs/plugin-react';
import tailwind from '@tailwindcss/vite';
import {fileURLToPath} from 'node:url';
const here=(p)=>fileURLToPath(new URL(p,import.meta.url));
export default defineConfig({plugins:[react(),tailwind()],resolve:{alias:[{find:'@/lib/router',replacement:here('./router.tsx')},{find:'@paperclipai/shared',replacement:here('./vendor/shared/index.ts')},{find:'@',replacement:here('./vendor')}]},test:{include:['*.test.ts']},build:{outDir:'dist'},server:{host:'127.0.0.1'}});
