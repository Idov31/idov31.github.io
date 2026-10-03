import assert from 'node:assert/strict';
import {test} from 'node:test';
import React from 'react';
import {act} from 'react-dom/test-utils';
import {createRoot} from 'react-dom/client';
import {JSDOM} from 'jsdom';
import ArticleTelemetry from '../src/components/ArticleTelemetry';

test('article events retain attribution, deduplicate depth, and clean up on navigation', async () => {
    const dom = new JSDOM('<div id="root"></div><a id="outside" href="/about">About</a>', {
        url: 'https://idov31.github.io/posts/example?utm_source=test',
        pretendToBeVisual: true,
    });
    const {window} = dom;
    const originalDescriptors = new Map<string, PropertyDescriptor | undefined>();
    const globals = {
        window,
        document: window.document,
        Element: window.Element,
        ResizeObserver: class {
            observe() {}
            disconnect() {}
        },
        IS_REACT_ACT_ENVIRONMENT: true,
    };
    for (const [key, value] of Object.entries(globals)) {
        originalDescriptors.set(key, Object.getOwnPropertyDescriptor(globalThis, key));
        Object.defineProperty(globalThis, key, {value, configurable: true, writable: true});
    }

    const events: {name: string; parameters: Record<string, string | number>}[] = [];
    Object.assign(window, {
        gtag: (_command: string, name: string, parameters: Record<string, string | number>) => {
            events.push({name, parameters});
        },
    });
    Object.defineProperty(window, 'innerHeight', {value: 1000});
    const root = createRoot(window.document.getElementById('root')!);
    let top = 0;
    const flushProgress = async () => {
        window.dispatchEvent(new window.Event('scroll'));
        await new Promise<void>((resolve) => window.requestAnimationFrame(() => resolve()));
    };
    const click = (selector: string) => {
        const element = window.document.querySelector(selector)!;
        element.addEventListener('click', (event) => event.preventDefault(), {once: true});
        element.dispatchEvent(new window.MouseEvent('click', {bubbles: true, cancelable: true}));
    };

    try {
        await act(async () => {
            root.render(
                <div className="post-content">
                    <ArticleTelemetry title="Example article"/>
                    <a id="project" href="https://github.com/Idov31/example?token=omit">Project</a>
                    <article ref={(element) => {
                        if (element) element.getBoundingClientRect = () => ({
                            top, bottom: top + 4000, height: 4000, width: 800,
                            left: 0, right: 800, x: 0, y: top, toJSON: () => ({}),
                        });
                    }}>
                        <nav aria-label="Table of contents"><a id="toc" href="#section">Section</a></nav>
                        <a id="internal" href="/posts/other">Other article</a>
                        <div data-code-language="cpp">
                            <button id="toggle" data-article-code-toggle aria-expanded="false">Expand</button>
                            <pre><code id="code">example code</code></pre>
                        </div>
                    </article>
                </div>,
            );
        });
        await flushProgress();
        assert.deepEqual(events.map((event) => event.parameters.percent_scrolled), [25]);
        top = -2000;
        await flushProgress();
        await flushProgress();
        assert.deepEqual(events.map((event) => event.parameters.percent_scrolled), [25, 50, 75]);
        top = -3000;
        await flushProgress();
        assert.equal(events.at(-1)?.parameters.percent_scrolled, 100);

        click('#outside');
        assert.equal(events.length, 4);
        click('#toc');
        assert.equal(events.at(-1)?.name, 'article_toc_click');
        assert.equal(events.at(-1)?.parameters.link_type, 'section');
        click('#project');
        assert.equal(events.at(-1)?.parameters.link_url, 'https://github.com/Idov31/example');
        assert.equal(events.at(-1)?.parameters.link_type, 'external');
        click('#internal');
        assert.equal(events.at(-1)?.parameters.link_type, 'internal');
        click('#toggle');
        assert.equal(events.at(-1)?.parameters.action, 'expand');
        window.document.querySelector('#toggle')!.setAttribute('aria-expanded', 'true');
        click('#toggle');
        assert.equal(events.at(-1)?.parameters.action, 'collapse');

        const range = window.document.createRange();
        range.selectNodeContents(window.document.querySelector('#code')!);
        window.getSelection()!.addRange(range);
        window.document.body.dispatchEvent(new window.Event('copy', {bubbles: true}));
        assert.equal(events.at(-1)?.name, 'article_code_copy');
        assert.equal(events.at(-1)?.parameters.code_language, 'cpp');
        for (const event of events) {
            assert.equal(event.parameters.article_path, '/posts/example');
            assert.equal(event.parameters.page_location, 'https://idov31.github.io/posts/example');
            assert.equal(event.parameters.article_title, 'Example article');
            assert.equal(event.parameters.page_title, 'Example article');
        }

        const count = events.length;
        await act(async () => root.unmount());
        window.document.body.dispatchEvent(new window.Event('copy', {bubbles: true}));
        await flushProgress();
        assert.equal(events.length, count);
    } finally {
        dom.window.close();
        for (const [key, descriptor] of originalDescriptors) {
            if (descriptor) Object.defineProperty(globalThis, key, descriptor);
            else Reflect.deleteProperty(globalThis, key);
        }
    }
});
