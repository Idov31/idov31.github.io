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
                bgBar: "#1E1E1E",
                bgHomeLine: "#1F2544",
                bgRegular: "#121526",
                bgLink: "#2D63D8",
                bgInsideDiv: "rgba(45, 50, 80, 0.40)",
                bgSemiTransparent: "rgba(68, 71, 90, 0.75)"
            },
            fontSize: {
                'md': '17px',
            },
            fontFamily: {
                'lato': ['Lato', 'sans-serif'],
            },
            width: {
                '1/8': '12.5%',
                '1/7': '14.2857143%',
            },
            height: {
              'h-100': '100px',
            },
        },
    },
    plugins: [],
};
export default config;
