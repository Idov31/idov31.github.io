'use client';

import {useEffect, useRef} from 'react';

type EventParameters = Record<string, string | number>;
type AnalyticsWindow = Window & {
    gtag?: (command: 'event', name: string, parameters: EventParameters) => void;
};

export default function ArticleTelemetry({title}: {title: string}) {
    const markerRef = useRef<HTMLSpanElement>(null);

    useEffect(() => {
        const container = markerRef.current?.closest<HTMLElement>('.post-content');
        const article = container?.querySelector('article');
        if (!container || !article) return;

        const path = window.location.pathname;
        const location = new URL(path, window.location.origin).href;
        const milestones = new Set<number>();
        let frame: number | undefined;

        const send = (name: string, parameters: EventParameters = {}): boolean => {
            const gtag = (window as AnalyticsWindow).gtag;
            if (!gtag) return false;
            gtag('event', name, {
                ...parameters,
                article_path: path,
                article_title: title,
                page_location: location,
                page_title: title,
            });
            return true;
        };

        const measureProgress = () => {
            frame = undefined;
            if (document.visibilityState !== 'visible') return;
            const bounds = article.getBoundingClientRect();
            if (bounds.height <= 0 || bounds.top >= window.innerHeight || bounds.bottom <= 0) return;
            // Measures how much of the article has entered the viewport, not proof of reading.
            const percent = Math.min(100, Math.max(0,
                (window.innerHeight - bounds.top) / bounds.height * 100));
            for (const milestone of [25, 50, 75, 100]) {
                if (percent >= milestone && !milestones.has(milestone)
                    && send('article_scroll', {percent_scrolled: milestone})) {
                    milestones.add(milestone);
                }
            }
        };

        const scheduleProgress = () => {
            if (frame === undefined) frame = window.requestAnimationFrame(measureProgress);
        };

        const handleClick = (event: MouseEvent) => {
            const target = event.target instanceof Element ? event.target : null;
            const toggle = target?.closest<HTMLButtonElement>('[data-article-code-toggle]');
            if (toggle && container.contains(toggle)) {
                send('article_code_toggle', {
                    action: toggle.getAttribute('aria-expanded') === 'true' ? 'collapse' : 'expand',
                    code_language: toggle.closest<HTMLElement>('[data-code-language]')?.dataset.codeLanguage ?? '',
                });
                return;
            }

            const link = target?.closest<HTMLAnchorElement>('a[href]');
            if (!link || !container.contains(link)) return;
            const url = new URL(link.href, window.location.href);
            if (!['http:', 'https:'].includes(url.protocol)) return;
            const isToc = Boolean(link.closest('nav[aria-label="Table of contents"]'));
            const isSection = url.origin === window.location.origin && url.pathname === path && Boolean(url.hash);
            send(isToc ? 'article_toc_click' : 'article_link_click', {
                link_url: `${url.origin}${url.pathname}${url.hash}`,
                link_type: isSection ? 'section' : url.origin === window.location.origin ? 'internal' : 'external',
            });
        };

        const handleCopy = (event: ClipboardEvent) => {
            const target = event.target instanceof Element ? event.target : null;
            const code = target?.closest<HTMLElement>('[data-code-language]');
            const selection = window.getSelection();
            const selectedElement = selection?.anchorNode?.parentElement;
            const selectedCode = selectedElement?.closest<HTMLElement>('[data-code-language]');
            const block = code ?? selectedCode;
            if (block && container.contains(block) && selection && !selection.isCollapsed) {
                send('article_code_copy', {code_language: block.dataset.codeLanguage ?? ''});
            }
        };

        container.addEventListener('click', handleClick, true);
        document.addEventListener('copy', handleCopy);
        window.addEventListener('scroll', scheduleProgress, {passive: true});
        window.addEventListener('resize', scheduleProgress);
        document.addEventListener('visibilitychange', scheduleProgress);
        const resizeObserver = new ResizeObserver(scheduleProgress);
        resizeObserver.observe(article);
        // Retry early milestones if the afterInteractive GA script has not initialized yet.
        const initializationTimer = window.setInterval(() => {
            if ((window as AnalyticsWindow).gtag) {
                window.clearInterval(initializationTimer);
                scheduleProgress();
            }
        }, 1000);
        scheduleProgress();

        return () => {
            container.removeEventListener('click', handleClick, true);
            document.removeEventListener('copy', handleCopy);
            window.removeEventListener('scroll', scheduleProgress);
            window.removeEventListener('resize', scheduleProgress);
            document.removeEventListener('visibilitychange', scheduleProgress);
            resizeObserver.disconnect();
            window.clearInterval(initializationTimer);
            if (frame !== undefined) window.cancelAnimationFrame(frame);
        };
    }, [title]);

    return <span ref={markerRef} hidden/>;
}
