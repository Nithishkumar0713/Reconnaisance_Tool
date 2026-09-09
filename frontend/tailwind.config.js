export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      fontFamily: {
        mono: ['"JetBrains Mono"', 'ui-monospace', 'monospace'],
        sans: ['Outfit', 'system-ui', 'sans-serif'],
      },
      colors: {
        natural: {
          bg: '#f0f4f8',      // Cool slate-blue base background
          card: '#ffffff',    // Clean white
          border: '#e2e8f0',  // Slate-200 border
          text: '#0f172a',    // Slate-900 text
          muted: '#475569',   // Slate-600 muted text
          accent: '#0d9488',  // Teal-600 accent
          accentHover: '#0f766e',
          accentLight: '#f0fdfa',
        },
      },
    },
  },
  plugins: [],
}
