/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['"Geist Variable"', '"Segoe UI Variable Text"', '"Segoe UI"', 'system-ui', 'sans-serif'],
        serif: ['"Instrument Serif"', 'Georgia', 'serif'],
        display: ['"Bricolage Grotesque Variable"', '"Geist Variable"', 'system-ui', 'sans-serif'],
        mono: ['"Geist Mono Variable"', 'ui-monospace', 'Consolas', 'monospace'],
      },
      colors: {
        ink: { DEFAULT: '#eafaf3', 2: '#dcefe6', 3: '#ffffff' },
        onink: '#03140d',
        canvas: '#030a07',
        surface: { DEFAULT: '#08150f', 2: '#0c1f17', 3: '#112a1f' },
        line: '#14291f',
        text: '#eafaf3',
        sub: '#b3cfc3',
        mute: '#8fb3a4',
        ember: { DEFAULT: '#ff7a45', dark: '#ff9a6b', soft: 'rgba(255,122,69,.14)' },
        calm: { DEFAULT: '#2ee6a6', dark: '#2ee6a6', soft: 'rgba(46,230,166,.12)' },
        warn: { DEFAULT: '#ffc15a', soft: 'rgba(255,193,90,.12)', line: '#5a4417' },
        danger: { DEFAULT: '#ff6b6b', soft: 'rgba(255,107,107,.13)' },
        brand: { DEFAULT: '#7ea1ff', soft: 'rgba(126,161,255,.14)' },
      },
      borderRadius: { xl: '14px', '2xl': '20px', '3xl': '28px' },
      boxShadow: {
        soft: '0 1px 0 rgba(255,255,255,.03) inset, 0 18px 40px -22px rgba(0,0,0,.7)',
        lift: '0 1px 0 rgba(255,255,255,.04) inset, 0 30px 60px -24px rgba(0,0,0,.85)',
      },
      keyframes: {
        ping2: { '75%,100%': { transform: 'scale(2.2)', opacity: '0' } },
        spinslow: { to: { transform: 'rotate(360deg)' } },
      },
      animation: { ping2: 'ping2 1.8s cubic-bezier(0,0,.2,1) infinite', spinslow: 'spinslow 7s linear infinite' },
    },
  },
  plugins: [],
};
