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
                txtHeader: "#BD93F9",
                txtSubHeader: "#CEAEFC",
                txtRegular: "#F8F8F2",
                txtLink: "#8BE9FD",
                txtInlineCode: "#FFD0EC",
                txtMuted: "#9CA3AF",
                bgBar: "#0d1117",
                bgHomeLine: "#1F2544",
                bgRegular: "#0a0e1a",
                bgCard: "#0f1629",
                bgLink: "#2D63D8",
                bgInsideDiv: "rgba(15, 22, 41, 0.85)",
                bgSemiTransparent: "rgba(13, 17, 23, 0.90)",
                borderAccent: "rgba(139, 233, 253, 0.15)",
                borderPurple: "rgba(189, 147, 249, 0.25)",
            },
            fontSize: {
                'md': '17px',
            },
            fontFamily: {
                'lato': ['Lato', 'sans-serif'],
                'cinzel': ['Cinzel', 'serif'],
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
                card: '0 4px 24px rgba(0,0,0,0.4)',
                glow: '0 0 20px rgba(189,147,249,0.3)',
                'glow-cyan': '0 0 20px rgba(139,233,253,0.2)',
            },
            animation: {
                'fade-in': 'fadeIn 0.4s ease-in-out',
            },
            keyframes: {
                fadeIn: {
                    '0%': {opacity: '0', transform: 'translateY(8px)'},
                    '100%': {opacity: '1', transform: 'translateY(0)'},
                },
            },
        },
    },
    plugins: [],
};
export default config;
