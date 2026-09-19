'use client';

import { useEffect, useId, useRef, useState } from 'react';

export interface MermaidDiagramProps {
    definition: string;
    caption?: string;
}

function themeValue(name: string, fallback: string): string {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fallback;
}

export default function MermaidDiagram({ definition, caption }: MermaidDiagramProps) {
    const containerRef = useRef<HTMLDivElement>(null);
    const reactId = useId().replace(/[^a-zA-Z0-9_-]/g, '');
    const [isLoading, setIsLoading] = useState(true);
    const [hasError, setHasError] = useState(false);

    useEffect(() => {
        let cancelled = false;

        const renderDiagram = async (): Promise<void> => {
            setIsLoading(true);
            setHasError(false);

            try {
                const { default: mermaid } = await import('mermaid');
                const isDark = document.documentElement.classList.contains('dark');
                mermaid.initialize({
                    startOnLoad: false,
                    securityLevel: 'strict',
                    secure: ['securityLevel', 'startOnLoad', 'theme', 'themeVariables', 'themeCSS', 'fontFamily'],
                    theme: 'base',
                    fontFamily: 'Lato, sans-serif',
                    themeVariables: {
                        darkMode: isDark,
                        background: themeValue('--bg-regular', isDark ? '#0D1117' : '#FFFFFF'),
                        primaryColor: themeValue('--bg-surface', isDark ? '#161B2E' : '#F5F3FF'),
                        primaryTextColor: themeValue('--txt-regular', isDark ? '#E2E8F0' : '#1E1B4B'),
                        primaryBorderColor: themeValue('--txt-subheader', isDark ? '#A78BFA' : '#6D28D9'),
                        tertiaryColor: themeValue('--bg-surface', isDark ? '#161B2E' : '#F5F3FF'),
                        lineColor: themeValue('--txt-subheader', isDark ? '#A78BFA' : '#6D28D9'),
                        textColor: themeValue('--txt-regular', isDark ? '#E2E8F0' : '#1E1B4B'),
                    },
                });
                const result = await mermaid.render(`mermaid-${reactId}`, definition);
                if (cancelled || !containerRef.current) return;

                containerRef.current.innerHTML = result.svg;
                result.bindFunctions?.(containerRef.current);
                setHasError(false);
            } catch {
                if (!cancelled) setHasError(true);
            } finally {
                if (!cancelled) setIsLoading(false);
            }
        };

        void renderDiagram();
        const observer = new MutationObserver(() => { void renderDiagram(); });
        observer.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] });

        return () => {
            cancelled = true;
            observer.disconnect();
            if (containerRef.current) containerRef.current.innerHTML = '';
        };
    }, [definition, reactId]);

    return (
        <figure className="pt-4 pb-2">
            <div className="rounded-xl border border-borderSubtle bg-bgInsideDiv p-4 md:p-6">
                {hasError ? (
                    <p className="text-sm text-txtMuted" role="alert">Unable to render this Mermaid diagram.</p>
                ) : (
                    <div
                        ref={containerRef}
                        className="mermaid-diagram min-h-32 overflow-x-auto text-center"
                        role="img"
                        aria-label={caption ?? 'Mermaid diagram'}
                        aria-busy={isLoading}
                    />
                )}
            </div>
            {caption && <figcaption className="pt-2 text-center text-sm italic text-txtSubHeader">{caption}</figcaption>}
        </figure>
    );
}
