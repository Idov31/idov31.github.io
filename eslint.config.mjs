import nextCoreWebVitals from 'eslint-config-next/core-web-vitals';

const config = [
    ...nextCoreWebVitals,
    {
        ignores: ['.next/**', 'out/**'],
    },
];

export default config;
