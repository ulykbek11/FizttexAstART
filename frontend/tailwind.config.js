/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        primary: '#2779A7',
        cyan: '#00D9FF',
        danger: '#E63946',
        success: '#06D6A0',
        warning: '#FFB700',
        dark: '#0F1419',
        darker: '#090C10',
      }
    },
  },
  plugins: [],
}
