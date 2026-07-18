import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        // Obsidian & Liquid Chrome Core
        obsidian: {
          DEFAULT: "#000000",
          surface: "#08080A",
          glass: "rgba(10, 10, 12, 0.7)",
          border: "rgba(255, 255, 255, 0.08)",
        },
        mercury: {
          50: "#FFFFFF",
          100: "#F2F2F2",
          200: "#E6E6E6",
          300: "#CCCCCC",
          400: "#999999",
          500: "#666666",
        },
        nebula: {
          purple: "#A78BFA",
          blue: "#60A5FA",
          cyan: "#22D3EE",
        },
        // Semantic
        background: "#000000",
        surface: "#08080A",
        text: {
          primary: "#FFFFFF",
          secondary: "#A1A1AA",
          muted: "#52525B",
        }
      },
      backgroundImage: {
        "liquid-chrome": "linear-gradient(135deg, #FFFFFF 0%, #D1D1D1 20%, #9E9E9E 40%, #FFFFFF 50%, #9E9E9E 60%, #D1D1D1 80%, #FFFFFF 100%)",
        "deep-metal": "linear-gradient(to bottom, #1A1A1A, #000000)",
        "obsidian-shine": "linear-gradient(110deg, transparent 40%, rgba(255,255,255,0.05) 45%, rgba(255,255,255,0.1) 50%, rgba(255,255,255,0.05) 55%, transparent 60%)",
        "radial-nebula": "radial-gradient(circle at center, rgba(96, 165, 250, 0.15) 0%, transparent 70%)",
      },
      boxShadow: {
        'liquid': '0 0 30px rgba(255, 255, 255, 0.1), inset 0 1px 1px rgba(255, 255, 255, 0.2)',
        'obsidian-lg': '0 20px 50px rgba(0, 0, 0, 0.9), 0 0 1px 1px rgba(255, 255, 255, 0.05)',
        'specular': 'inset 0 2px 4px rgba(255, 255, 255, 0.2), inset 0 -2px 4px rgba(0, 0, 0, 0.8)',
        'blue-glow': '0 0 50px -10px rgba(59, 130, 246, 0.3)',
      },
      animation: {
        'liquid-flow': 'liquid-flow 3s ease-in-out infinite',
        'obsidian-pulse': 'obsidian-pulse 4s ease-in-out infinite',
        'glint': 'glint 2s linear infinite',
      },
      keyframes: {
        'liquid-flow': {
          '0%, 100%': { transform: 'translateY(0) scale(1)' },
          '50%': { transform: 'translateY(-5px) scale(1.02)' },
        },
        'obsidian-pulse': {
          '0%, 100%': { opacity: '0.8', filter: 'brightness(1)' },
          '50%': { opacity: '1', filter: 'brightness(1.2)' },
        },
        glint: {
          '0%': { backgroundPosition: '-200% center' },
          '100%': { backgroundPosition: '200% center' },
        },
      },
    },
  },
  plugins: [],
};
export default config;

