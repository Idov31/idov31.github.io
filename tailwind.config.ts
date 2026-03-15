import type {Config} from "tailwindcss";

const config: Config = {
    content: [
        "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
        "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
        "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
    ],
    theme: {
        extend: {
            colors: {
                txtHeader: "#C4B5FD",
                txtSubHeader: "#A78BFA",
                txtRegular: "#E2E8F0",
                txtMuted: "#94A3B8",
                txtLink: "#38BDF8",
                txtInlineCode: "#F9A8D4",
                bgBar: "#0D1117",
                bgNavBorder: "rgba(139, 92, 246, 0.2)",
                bgHomeLine: "#1A1F3A",
                bgRegular: "#0D1117",
                bgSurface: "#161B2E",
                bgCard: "rgba(22, 27, 46, 0.8)",
                bgLink: "#1D4ED8",
                bgInsideDiv: "rgba(22, 27, 46, 0.85)",
                bgSemiTransparent: "rgba(30, 35, 60, 0.85)",
                bgCodeBlock: "#1E1E2E",
                accentPurple: "#7C3AED",
                accentBlue: "#0EA5E9",
                accentGlow: "rgba(124, 58, 237, 0.4)",
                borderSubtle: "rgba(139, 92, 246, 0.15)",
                borderMid: "rgba(139, 92, 246, 0.3)",
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
