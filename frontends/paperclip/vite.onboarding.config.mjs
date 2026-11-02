import {defineConfig} from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
export default defineConfig({resolve:{alias:{'@':new URL('./vendor',import.meta.url).pathname,'@paperclipai/shared':new URL('./vendor/shared/index.ts',import.meta.url).pathname}},plugins:[react(),tailwindcss()],build:{outDir:'dist-onboarding',rollupOptions:{input:'onboarding-demo.html'}}});
