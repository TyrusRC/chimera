/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        chimera: {
          bg: '#1e1e2e',
          surface: '#24243e',
          panel: '#2a2a4a',
          border: '#3a3a5a',
          text: '#cdd6f4',
          muted: '#6c7086',
          accent: '#89b4fa',
          critical: '#f38ba8',
          high: '#fab387',
          medium: '#f9e2af',
          low: '#a6e3a1',
        },
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
      },
    },
  },
  plugins: [],
}
