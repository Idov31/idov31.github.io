import type {Config} from "tailwindcss";

const config: Config = {
    content: [
        "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
        "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
        "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
    ],
    darkMode: 'class',
    theme: {
        extend: {
            colors: {
                // Text colors — themed via CSS variables
                txtHeader: "var(--txt-header)",
                txtSubHeader: "var(--txt-subheader)",
                txtRegular: "var(--txt-regular)",
                txtMuted: "var(--txt-muted)",
                // Channel-format vars so opacity modifiers (e.g. /30) work correctly
                txtLink: "rgb(var(--txt-link-rgb) / <alpha-value>)",
                txtInlineCode: "var(--txt-inline-code)",
                // Background colors — themed via CSS variables
                bgBar: "rgb(var(--bg-bar-rgb) / <alpha-value>)",
                bgRegular: "var(--bg-regular)",
                bgSurface: "var(--bg-surface)",
                bgInsideDiv: "var(--bg-inside-div)",
                bgSemiTransparent: "var(--bg-semi-transparent)",
                bgHomeLine: "#1A1F3A",
                bgLink: "#1D4ED8",
                bgCard: "var(--bg-inside-div)",
                bgCodeBlock: "#1E1E2E",
                // Accent — same in both themes, channel format for opacity modifiers
                accentPurple: "rgb(var(--accent-purple-rgb) / <alpha-value>)",
                accentBlue: "#0EA5E9",
                accentGlow: "rgba(124, 58, 237, 0.4)",
                // Border colors — themed via CSS variables
                borderSubtle: "var(--border-subtle)",
                borderMid: "var(--border-mid)",
                bgNavBorder: "rgba(139, 92, 246, 0.2)",
            },
            fontSize: {
                'md': '17px',
            },
            fontFamily: {
                'lato': ['Lato', 'sans-serif'],
                'mono': ['JetBrains Mono', 'Fira Code', 'Cascadia Code', 'monospace'],
            },
            width: {
                '1/8': '12.5%',
                '1/7': '14.2857143%',
            },
            height: {
                'h-100': '100px',
            },
            backdropBlur: {
                xs: '2px',
            },
            boxShadow: {
                glow: '0 0 20px rgba(124, 58, 237, 0.3)',
                'glow-blue': '0 0 20px rgba(14, 165, 233, 0.3)',
                card: '0 4px 24px rgba(0, 0, 0, 0.4)',
            },
            animation: {
                'fade-in': 'fadeIn 0.5s ease-in-out',
                'slide-up': 'slideUp 0.4s ease-out',
            },
            keyframes: {
                fadeIn: {
                    '0%': { opacity: '0' },
                    '100%': { opacity: '1' },
                },
                slideUp: {
                    '0%': { transform: 'translateY(10px)', opacity: '0' },
                    '100%': { transform: 'translateY(0)', opacity: '1' },
                },
            },
        },
    },
    plugins: [],
};
export default config;
