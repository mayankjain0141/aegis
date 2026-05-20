export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        base: '#09090b',
        raised: '#111113',
        panel: '#18181b',
        deny: '#ef4444',
        allow: '#22c55e',
        escalate: '#f59e0b',
        phase1: '#3b82f6',
        phase2: '#a855f7',
        phase3: '#f97316',
        border: {
          faint: '#1f1f23',
          DEFAULT: '#27272a',
          strong: '#3f3f46',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Menlo', 'monospace'],
      },
      fontSize: {
        '10': '10px',
        '12': '12px',
        '13': '13px',
        '14': '14px',
        '16': '16px',
        '18': '18px',
      },
      spacing: {
        '1': '4px',
        '2': '8px',
        '3': '12px',
        '4': '16px',
        '5': '20px',
        '6': '24px',
      },
      borderRadius: {
        DEFAULT: '6px',
      },
    },
  },
  plugins: [],
}
