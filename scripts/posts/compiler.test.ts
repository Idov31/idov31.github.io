import assert from 'node:assert/strict';
import { chmod, mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { compilePost } from './compiler';

const fixturePath = path.join(process.cwd(), 'scripts', 'posts', 'fixtures', 'all-features.md');

function frontmatter(overrides = ''): string {
    return `---
formatVersion: 1
slug: test-post
title: "Test Post"
date: "2026-05-02"
projectLink: "https://github.com/example/test"
summary: "Test summary"
cardImage: "/post-images/test/card.png"
cardImageAlt: "Test card"
${overrides}---\n`;
}

function errors(markdown: string): string[] {
    return compilePost(markdown).diagnostics.map((entry) => entry.message);
}

async function removeTemporaryWorkspace(temporary: string): Promise<void> {
    let lastError: unknown;
    for (let attempt = 0; attempt < 12; attempt += 1) {
        try {
            await rm(temporary, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
            return;
        } catch (error) {
            lastError = error;
            await new Promise<void>((resolve) => setTimeout(resolve, 100 * (attempt + 1)));
        }
    }
    throw lastError;
}

test('compiler maps the complete supported Markdown format deterministically', async () => {
    const source = await readFile(fixturePath, 'utf8');
    const first = compilePost(source, fixturePath);
    const second = compilePost(source, fixturePath);

    assert.deepEqual(first.diagnostics, []);
    assert.equal(first.generatedTsx, second.generatedTsx);
    const output = first.generatedTsx ?? '';
    for (const expected of [
        '<BlogPrologue', '<TableOfContents />', 'drop-caps pt-4', '<SecondaryHeader', '<ThirdHeader',
        '<strong>', '<em>', '<del>', '<InlineCode', '<StyledLink', '<br />', '<BulletList',
        '<NumberedList', '<BlogImageFigure', 'caption={"Caption"}', 'sourceHref={"https://example.com/source"}',
        '<Code text={codeBlock1}', 'isMessageToggled={true}', '<RoadmapTimeline', 'const codeBlock1',
    ]) assert.match(output, new RegExp(expected.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
});

test('compiler rejects malformed or unsafe frontmatter and roadmap YAML', () => {
    assert.ok(errors(`${frontmatter('unknown: value\n')}Body`).some((value) => value.includes('Unknown frontmatter key')));
    assert.ok(errors(`${frontmatter('slug: other\n')}Body`).some((value) => value.includes('Map keys must be unique')));
    assert.ok(errors(`${frontmatter().replace('date: "2026-05-02"', 'date: "2026-02-30"')}Body`).some((value) => value.includes('real ISO calendar date')));
    assert.ok(errors(`${frontmatter().replace('projectLink: "https://github.com/example/test"', 'projectLink: "javascript:alert(1)"')}Body`).some((value) => value.includes('projectLink')));
    assert.ok(errors(`${frontmatter().replace('cardImage: "/post-images/test/card.png"', 'cardImage: "/post-images/../escape.png"')}Body`).some((value) => value.includes('cardImage')));
    assert.ok(errors(`${frontmatter()}:::roadmap\n\`\`\`yaml\nitems:\n  - version: 1\n    description: okay\n\`\`\`\n:::`).some((value) => value.includes('Roadmap YAML')));
});

test('compiler rejects raw JSX/HTML and unsupported AST constructs', () => {
    for (const body of [
        '<script>alert(1)</script>', '<Component />', '# H1', '#### H4', '> quote', '| a | b |\n| - | - |\n| 1 | 2 |',
        '- parent\n  - nested', '- [ ] task', ':::unknown\ntext\n:::', '---',
    ]) {
        const result = compilePost(`${frontmatter()}\n${body}`);
        assert.notEqual(result.diagnostics.length, 0, body);
        assert.ok(result.diagnostics.every((entry) => entry.line >= 1 && entry.column >= 1));
    }
});

test('compiler rejects unsafe block and inline resource paths and URLs', () => {
    for (const body of [
        '![x](/post-images/../escape.png)', '::image{src="/post-images/a.png" alt="a" sourceHref="javascript:alert(1)"}',
        '[bad](javascript:alert(1))', '[traversal](/posts/../admin)', '```cpp strange=value\ncode\n```',
    ]) assert.notEqual(compilePost(`${frontmatter()}\n${body}`).diagnostics.length, 0, body);
});

test('compiler supports a plain image paragraph and omits unused optional imports', () => {
    const imageOnly = compilePost(`${frontmatter()}\n![Image](/post-images/test/card.png)`);
    assert.deepEqual(imageOnly.diagnostics, []);
    assert.match(imageOnly.generatedTsx ?? '', /<BlogImageFigure src=\{"\/post-images\/test\/card\.png"\}/);

    const minimal = compilePost(`${frontmatter()}\nA plain paragraph.`);
    assert.deepEqual(minimal.diagnostics, []);
    assert.doesNotMatch(minimal.generatedTsx ?? '', /RoadmapTimeline/);
    assert.doesNotMatch(minimal.generatedTsx ?? '', /BlogImageFigure/);
    assert.doesNotMatch(minimal.generatedTsx ?? '', /\bCode\b/);
});

test('publisher check is write-free and publish replaces only its synthetic slug and index entry', async () => {
    const temporary = await mkdtemp(path.join(os.tmpdir(), 'markdown-posts-test-'));
    const originalCwd = process.cwd();
    let indexPath: string | undefined;
    try {
        await mkdir(path.join(temporary, 'drafts'), { recursive: true });
        await mkdir(path.join(temporary, 'public', 'post-images', 'test'), { recursive: true });
        await mkdir(path.join(temporary, 'src', 'data'), { recursive: true });
        await writeFile(path.join(temporary, 'public', 'post-images', 'test', 'card.png'), 'image');
        indexPath = path.join(temporary, 'src', 'data', 'blogPosts.ts');
        await writeFile(indexPath, `export const blogPosts = [\n    { href: '/posts/older', headerContent: 'Older', subHeaderContent: '01 Jan 2020', imagePath: '/post-images/test/card.png', imageAlt: 'old', imageWidth: 1, imageHeight: 1, postContent: 'old' },\n];\n`);
        await writeFile(path.join(temporary, 'drafts', 'test.md'), `${frontmatter()}\n## A section`);
        process.chdir(temporary);
        const { checkDraft, publishDraft } = await import(`./publisher?temporary=${Date.now()}`);

        const beforeIndex = await readFile(path.join(temporary, 'src', 'data', 'blogPosts.ts'), 'utf8');
        assert.deepEqual(await checkDraft('drafts/test.md'), { diagnostics: [], published: false });
        assert.equal(await readFile(path.join(temporary, 'src', 'data', 'blogPosts.ts'), 'utf8'), beforeIndex);
        await assert.rejects(readFile(path.join(temporary, 'src', 'app', 'posts', 'test-post', 'page.tsx')));
        assert.equal((await checkDraft('../outside.md')).published, false);

        assert.deepEqual(await publishDraft('drafts/test.md'), { diagnostics: [], published: true });
        const firstPage = await readFile(path.join(temporary, 'src', 'app', 'posts', 'test-post', 'page.tsx'), 'utf8');
        const firstIndex = await readFile(path.join(temporary, 'src', 'data', 'blogPosts.ts'), 'utf8');
        assert.match(firstPage, /Test Post/);
        assert.equal((firstIndex.match(/\/posts\/test-post/g) ?? []).length, 1);
        assert.ok(firstIndex.indexOf('/posts/test-post') < firstIndex.indexOf('/posts/older'));

        const replacedDraft = frontmatter()
            .replace('title: "Test Post"', 'title: "Replaced Post"')
            .replace('summary: "Test summary"', 'summary: "Replaced summary"');
        await writeFile(path.join(temporary, 'drafts', 'test.md'), `${replacedDraft}\n## Replaced`);
        await chmod(indexPath, 0o444);
        const failedPublish = await publishDraft('drafts/test.md');
        await chmod(indexPath, 0o644);
        assert.equal(failedPublish.published, false);
        assert.match(failedPublish.diagnostics[0]?.message ?? '', /^Unable to publish draft:/);
        assert.equal(await readFile(path.join(temporary, 'src', 'app', 'posts', 'test-post', 'page.tsx'), 'utf8'), firstPage);
        assert.equal(await readFile(path.join(temporary, 'src', 'data', 'blogPosts.ts'), 'utf8'), firstIndex);

        assert.equal((await publishDraft('drafts/test.md')).published, true);
        const secondPage = await readFile(path.join(temporary, 'src', 'app', 'posts', 'test-post', 'page.tsx'), 'utf8');
        const secondIndex = await readFile(path.join(temporary, 'src', 'data', 'blogPosts.ts'), 'utf8');
        assert.notEqual(firstPage, secondPage);
        assert.match(secondPage, /Replaced Post/);
        assert.equal((secondIndex.match(/\/posts\/test-post/g) ?? []).length, 1);
        assert.match(secondIndex, /Replaced summary/);
    } finally {
        process.chdir(originalCwd);
        if (indexPath) await chmod(indexPath, 0o644).catch(() => undefined);
        await removeTemporaryWorkspace(temporary);
    }
});
