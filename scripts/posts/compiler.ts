import { isMap, parseDocument } from 'yaml';
import { unified } from 'unified';
import remarkDirective from 'remark-directive';
import remarkFrontmatter from 'remark-frontmatter';
import remarkGfm from 'remark-gfm';
import remarkParse from 'remark-parse';
import type { CompilePostResult, PostDiagnostic, PostFrontmatter, RoadmapData, RoadmapItem } from './types';

interface Position {
    start?: { line?: number; column?: number };
}

interface MarkdownNode {
    type: string;
    value?: string;
    depth?: number;
    lang?: string | null;
    meta?: string | null;
    url?: string;
    alt?: string;
    title?: string | null;
    name?: string;
    attributes?: Record<string, string | null | undefined>;
    checked?: boolean | null;
    ordered?: boolean;
    children?: MarkdownNode[];
    position?: Position;
}

interface CompilerState {
    diagnostics: PostDiagnostic[];
    codeBlocks: Array<{ name: string; value: string }>;
}

const processor = unified().use(remarkParse).use(remarkGfm).use(remarkFrontmatter, ['yaml']).use(remarkDirective);
const requiredFrontmatterKeys = ['formatVersion', 'slug', 'title', 'date', 'projectLink', 'summary', 'cardImage', 'cardImageAlt'] as const;
const allowedFrontmatterKeys = new Set([...requiredFrontmatterKeys, 'cardImageWidth', 'cardImageHeight', 'sub']);

export function compilePost(markdown: string, sourcePath = '<input>'): CompilePostResult {
    const state: CompilerState = { diagnostics: [], codeBlocks: [] };
    let root: MarkdownNode;

    try {
        root = processor.parse(markdown) as unknown as MarkdownNode;
    } catch (error) {
        addDiagnostic(state, undefined, `Unable to parse ${sourcePath}: ${messageOf(error)}`, 'syntax');
        return { diagnostics: state.diagnostics };
    }

    const frontmatterNodes = (root.children ?? []).filter((node) => node.type === 'yaml');
    if (frontmatterNodes.length !== 1 || root.children?.[0]?.type !== 'yaml') {
        addDiagnostic(state, root, 'A single YAML frontmatter block must be the first document node.', 'frontmatter');
        return { diagnostics: state.diagnostics };
    }

    const frontmatter = parseFrontmatter(frontmatterNodes[0], state);
    if (!frontmatter || state.diagnostics.length > 0) {
        return { diagnostics: state.diagnostics };
    }

    const body = (root.children ?? []).slice(1).map((node) => renderBlock(node, state)).filter(Boolean).join('\n');
    if (state.diagnostics.length > 0) {
        return { frontmatter, diagnostics: state.diagnostics };
    }

    return {
        frontmatter,
        generatedTsx: generatePage(frontmatter, body, state.codeBlocks),
        diagnostics: [],
    };
}

function parseFrontmatter(node: MarkdownNode, state: CompilerState): PostFrontmatter | undefined {
    const document = parseDocument(node.value ?? '', { prettyErrors: false, uniqueKeys: true });
    for (const error of document.errors) {
        addDiagnostic(state, node, `Invalid YAML frontmatter: ${error.message}`, 'frontmatter');
    }
    if (document.errors.length > 0 || !document.contents || !isMap(document.contents)) {
        if (document.errors.length === 0) addDiagnostic(state, node, 'Frontmatter must be a YAML mapping.', 'frontmatter');
        return undefined;
    }

    const values = document.toJS() as unknown;
    if (!isRecord(values)) {
        addDiagnostic(state, node, 'Frontmatter must be a YAML mapping.', 'frontmatter');
        return undefined;
    }

    for (const key of Object.keys(values)) {
        if (!allowedFrontmatterKeys.has(key)) addDiagnostic(state, node, `Unknown frontmatter key '${key}'.`, 'validation');
    }
    for (const key of requiredFrontmatterKeys) {
        if (!(key in values)) addDiagnostic(state, node, `Missing required frontmatter key '${key}'.`, 'validation');
    }
    if (state.diagnostics.length > 0) return undefined;

    const stringValue = (key: string): string | undefined => {
        const value = values[key];
        if (typeof value !== 'string' || value.trim() === '') {
            addDiagnostic(state, node, `Frontmatter '${key}' must be a non-empty string.`, 'validation');
            return undefined;
        }
        return value;
    };
    const formatVersion = values.formatVersion;
    if (formatVersion !== 1) addDiagnostic(state, node, "Frontmatter 'formatVersion' must be 1.", 'validation');
    const slug = stringValue('slug');
    const title = stringValue('title');
    const date = stringValue('date');
    const projectLink = stringValue('projectLink');
    const summary = stringValue('summary');
    const cardImage = stringValue('cardImage');
    const cardImageAlt = stringValue('cardImageAlt');
    const width = positiveInteger(values.cardImageWidth, 135, 'cardImageWidth', node, state);
    const height = positiveInteger(values.cardImageHeight, 51, 'cardImageHeight', node, state);
    const sub = booleanValue(values.sub, false, 'sub', node, state);

    if (!slug || !title || !date || !projectLink || !summary || !cardImage || !cardImageAlt || width === undefined || height === undefined || sub === undefined) return undefined;
    if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(slug)) addDiagnostic(state, node, "Frontmatter 'slug' must be lowercase hyphenated text.", 'validation');
    if (!isIsoDate(date)) addDiagnostic(state, node, "Frontmatter 'date' must be a real ISO calendar date (YYYY-MM-DD).", 'validation');
    if (!isAllowedUrl(projectLink)) addDiagnostic(state, node, "Frontmatter 'projectLink' must use http or https.", 'validation');
    if (!isPublicImagePath(cardImage)) addDiagnostic(state, node, "Frontmatter 'cardImage' must be a /post-images/ path without traversal.", 'validation');
    if (state.diagnostics.length > 0) return undefined;

    return { formatVersion: 1, slug, title, date, projectLink, summary, cardImage, cardImageAlt, cardImageWidth: width, cardImageHeight: height, sub };
}

function renderBlock(node: MarkdownNode, state: CompilerState): string {
    switch (node.type) {
        case 'text':
            return expression(node.value ?? '');
        case 'paragraph':
            if (node.children?.length === 1 && node.children[0].type === 'image') return renderImage(node.children[0], state);
            return `<div className="pt-4">${renderInlineChildren(node, state)}</div>`;
        case 'heading':
            if (node.depth === 2) return `<SecondaryHeader text={${expression(inlinePlainText(node, state))}} />`;
            if (node.depth === 3) return `<ThirdHeader text={${expression(inlinePlainText(node, state))}} />`;
            addDiagnostic(state, node, 'Only H2 and H3 headings are supported.', 'unsupported');
            return '';
        case 'code':
            return renderCode(node, state);
        case 'list':
            return renderList(node, state);
        case 'image':
            return renderImage(node, state);
        case 'html':
        case 'jsx':
        case 'mdxFlowExpression':
        case 'mdxJsxFlowElement':
        case 'mdxjsEsm':
            addDiagnostic(state, node, 'Raw HTML and JSX are not supported.', 'unsupported');
            return '';
        case 'blockquote':
        case 'table':
            addDiagnostic(state, node, `${node.type === 'blockquote' ? 'Blockquotes' : 'Tables'} are not supported.`, 'unsupported');
            return '';
        case 'thematicBreak':
            addDiagnostic(state, node, 'Thematic breaks are not supported.', 'unsupported');
            return '';
        case 'containerDirective':
            return renderContainerDirective(node, state);
        case 'leafDirective':
        case 'textDirective':
            return renderImageDirective(node, state);
        default:
            addDiagnostic(state, node, `Unsupported Markdown node '${node.type}'.`, 'unsupported');
            return '';
    }
}

function renderContainerDirective(node: MarkdownNode, state: CompilerState): string {
    if (node.name === 'lead') {
        const children = node.children ?? [];
        if (children.length === 0) {
            addDiagnostic(state, node, 'The lead directive cannot be empty.', 'validation');
            return '';
        }
        return `<div className="drop-caps pt-4">${children.map((child) => {
            if (child.type !== 'paragraph') addDiagnostic(state, child, 'The lead directive accepts paragraphs only.', 'unsupported');
            return child.type === 'paragraph' ? renderInlineChildren(child, state) : '';
        }).join('<br />')}</div>`;
    }
    if (node.name === 'roadmap') return renderRoadmap(node, state);
    addDiagnostic(state, node, `Unknown directive ':::${node.name ?? ''}'.`, 'unsupported');
    return '';
}

function renderImageDirective(node: MarkdownNode, state: CompilerState): string {
    if (node.name !== 'image') {
        addDiagnostic(state, node, `Unknown directive '::${node.name ?? ''}'.`, 'unsupported');
        return '';
    }
    if (node.type !== 'leafDirective') {
        addDiagnostic(state, node, 'The image directive must use leaf syntax (::image{...}).', 'unsupported');
        return '';
    }
    const attributes = node.attributes ?? {};
    const allowed = new Set(['src', 'alt', 'caption', 'sourceHref']);
    for (const key of Object.keys(attributes)) if (!allowed.has(key)) addDiagnostic(state, node, `Unknown image attribute '${key}'.`, 'validation');
    const src = attributes.src;
    const alt = attributes.alt;
    const caption = attributes.caption;
    const sourceHref = attributes.sourceHref;
    if (!src || !alt || !isPublicImagePath(src)) addDiagnostic(state, node, 'The image directive requires src=/post-images/... and non-empty alt.', 'validation');
    if (sourceHref && !isAllowedUrl(sourceHref)) addDiagnostic(state, node, 'Image sourceHref must be an allowed URL.', 'validation');
    if (state.diagnostics.length > 0 || !src || !alt) return '';
    return `<BlogImageFigure src={${expression(src)}} alt={${expression(alt)}}${caption ? ` caption={${expression(caption)}}` : ''}${sourceHref ? ` sourceHref={${expression(sourceHref)}}` : ''} />`;
}

function renderImage(node: MarkdownNode, state: CompilerState): string {
    if (!node.url || !node.alt || !isPublicImagePath(node.url)) {
        addDiagnostic(state, node, 'Markdown images require non-empty alt text and a /post-images/ source path.', 'validation');
        return '';
    }
    return `<BlogImageFigure src={${expression(node.url)}} alt={${expression(node.alt)}}${node.title ? ` caption={${expression(node.title)}}` : ''} />`;
}

function renderRoadmap(node: MarkdownNode, state: CompilerState): string {
    const children = node.children ?? [];
    if (children.length !== 1 || children[0].type !== 'code' || children[0].lang !== 'yaml') {
        addDiagnostic(state, node, 'The roadmap directive must contain exactly one fenced yaml block.', 'validation');
        return '';
    }
    const document = parseDocument(children[0].value ?? '', { prettyErrors: false, uniqueKeys: true });
    for (const error of document.errors) addDiagnostic(state, children[0], `Invalid roadmap YAML: ${error.message}`, 'validation');
    const data = document.toJS() as unknown;
    if (!isRoadmapData(data)) {
        addDiagnostic(state, children[0], 'Roadmap YAML must contain an items array with version and description strings.', 'validation');
        return '';
    }
    const title = data.title ? ` title={${expression(data.title)}}` : '';
    const description = data.description ? ` description={${expression(data.description)}}` : '';
    return `<RoadmapTimeline${title}${description} items={${jsonExpression(data.items)} as RoadmapItem[]} />`;
}

function renderCode(node: MarkdownNode, state: CompilerState): string {
    const language = node.lang || 'text';
    if (!/^[a-zA-Z0-9_+-]+$/.test(language)) {
        addDiagnostic(state, node, 'Code fence language contains unsupported characters.', 'validation');
        return '';
    }
    const meta = parseCodeMeta(node.meta ?? '', node, state);
    if (!meta) return '';
    const name = `codeBlock${state.codeBlocks.length + 1}`;
    state.codeBlocks.push({ name, value: node.value ?? '' });
    return `<Code text={${name}} language={${expression(language)}}${meta.collapsible ? ` message={${expression(meta.message)}} isMessageToggled={true}` : ''} />`;
}

function renderList(node: MarkdownNode, state: CompilerState): string {
    const items = node.children ?? [];
    if (items.length === 0 || items.some((item) => item.type !== 'listItem' || item.checked !== null && item.checked !== undefined || (item.children ?? []).length !== 1 || item.children?.[0]?.type !== 'paragraph')) {
        addDiagnostic(state, node, 'Only flat, non-task Markdown lists with one paragraph per item are supported.', 'unsupported');
        return '';
    }
    const contents = items.map((item) => `{ content: <>${renderInlineChildren(item.children![0], state)}</> }`).join(', ');
    return `<${node.ordered ? 'NumberedList' : 'BulletList'} items={[${contents}]} />`;
}

function renderInlineChildren(node: MarkdownNode, state: CompilerState): string {
    return (node.children ?? []).map((child) => renderInline(child, state)).join('');
}

function renderInline(node: MarkdownNode, state: CompilerState): string {
    switch (node.type) {
        case 'text': return expression(node.value ?? '');
        case 'emphasis': return `<em>${renderInlineChildren(node, state)}</em>`;
        case 'strong': return `<strong>${renderInlineChildren(node, state)}</strong>`;
        case 'delete': return `<del>${renderInlineChildren(node, state)}</del>`;
        case 'inlineCode': return `<InlineCode text={${expression(node.value ?? '')}} />`;
        case 'break': return '<br />';
        case 'link': {
            const content = inlinePlainText(node, state);
            if (!node.url || !content || !isAllowedUrl(node.url, true)) {
                addDiagnostic(state, node, 'Links require non-empty text and an internal path, fragment, http(s), or mailto URL.', 'validation');
                return '';
            }
            return `<StyledLink href={${expression(node.url)}} content={${expression(content)}} textSize="text-md" />`;
        }
        case 'image':
            addDiagnostic(state, node, 'Images must be block-level.', 'unsupported');
            return '';
        case 'html':
        case 'jsx':
        case 'mdxTextExpression':
        case 'mdxJsxTextElement':
            addDiagnostic(state, node, 'Raw HTML and JSX are not supported.', 'unsupported');
            return '';
        default:
            addDiagnostic(state, node, `Unsupported inline Markdown node '${node.type}'.`, 'unsupported');
            return '';
    }
}

function inlinePlainText(node: MarkdownNode, state: CompilerState): string {
    let value = '';
    const walk = (current: MarkdownNode): void => {
        if (current.type === 'text' || current.type === 'inlineCode') value += current.value ?? '';
        else if (current.type === 'break') value += ' ';
        else if (current.type === 'emphasis' || current.type === 'strong' || current.type === 'delete' || current.type === 'link') (current.children ?? []).forEach(walk);
        else addDiagnostic(state, current, `Unsupported content in heading or link: '${current.type}'.`, 'unsupported');
    };
    (node.children ?? []).forEach(walk);
    return value;
}

function parseCodeMeta(meta: string, node: MarkdownNode, state: CompilerState): { collapsible: boolean; message: string } | undefined {
    if (!meta.trim()) return { collapsible: false, message: '' };
    const match = /^collapsible\s+message=("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')$/.exec(meta.trim());
    if (!match) {
        addDiagnostic(state, node, 'Code fence metadata must be: collapsible message="...".', 'validation');
        return undefined;
    }
    const quote = match[1][0];
    const message = match[1].slice(1, -1).replace(new RegExp(`\\\\${quote}`, 'g'), quote).replace(/\\\\/g, '\\');
    if (!message) {
        addDiagnostic(state, node, 'Collapsible code message cannot be empty.', 'validation');
        return undefined;
    }
    return { collapsible: true, message };
}

function generatePage(frontmatter: PostFrontmatter, body: string, codeBlocks: Array<{ name: string; value: string }>): string {
    const componentName = `Post${pascalCase(frontmatter.slug)}`;
    const codeConstants = codeBlocks.map(({ name, value }) => `const ${name} = ${expression(value)};`).join('\n');
    const date = formatPrologueDate(frontmatter.date);
    const blogComponentNames = ['BlogPrologue'];
    if (body.includes('<BulletList')) blogComponentNames.push('BulletList');
    if (body.includes('<Code ')) blogComponentNames.push('Code');
    if (body.includes('<InlineCode')) blogComponentNames.push('InlineCode');
    if (body.includes('<NumberedList')) blogComponentNames.push('NumberedList');
    if (body.includes('<ThirdHeader')) blogComponentNames.push('ThirdHeader');
    const blogComponentsImport = body.includes('<SecondaryHeader')
        ? `import SecondaryHeader, { ${blogComponentNames.join(', ')} } from '@/components/BlogComponents';`
        : `import { ${blogComponentNames.join(', ')} } from '@/components/BlogComponents';`;
    const optionalImports = [
        body.includes('<BlogImageFigure') ? "import BlogImageFigure from '@/components/BlogImageFigure';" : '',
        body.includes('<RoadmapTimeline') ? "import RoadmapTimeline from '@/components/RoadmapTimeline';" : '',
        body.includes('<RoadmapTimeline') ? 'type RoadmapItem = { version: string; description: string; features?: string[]; bugfixes?: string[]; isCurrentRelease?: boolean; isCompleted?: boolean };' : '',
        body.includes('<StyledLink') ? "import StyledLink from '@/components/StyledLink';" : '',
    ].filter(Boolean).join('\n');
    return `'use client';

import { useEffect } from 'react';
${blogComponentsImport}
${optionalImports}
import TableOfContents from '@/components/TableOfContents';

${codeConstants}

export default function ${componentName}() {
    useEffect(() => {
        document.title = ${expression(frontmatter.title)};
    }, []);

    return (
        <div className="card-surface rounded-xl p-6 lg:p-8 animate-fade-in post-content">
            <BlogPrologue title={${expression(frontmatter.title)}} date={${expression(date)}} projectLink={${expression(frontmatter.projectLink)}} />
            <div className="pt-4">
                <article>
                    <TableOfContents />
                    ${body}
                </article>
            </div>
        </div>
    );
}
`;
}

function addDiagnostic(state: CompilerState, node: MarkdownNode | undefined, message: string, code: PostDiagnostic['code']): void {
    state.diagnostics.push({ message, code, line: node?.position?.start?.line ?? 1, column: node?.position?.start?.column ?? 1 });
}

function expression(value: string): string { return JSON.stringify(value).replace(/</g, '\\u003c').replace(/>/g, '\\u003e').replace(/&/g, '\\u0026'); }
function jsonExpression(value: unknown): string { return JSON.stringify(value).replace(/</g, '\\u003c').replace(/>/g, '\\u003e').replace(/&/g, '\\u0026'); }
function messageOf(error: unknown): string { return error instanceof Error ? error.message : String(error); }
function isRecord(value: unknown): value is Record<string, unknown> { return typeof value === 'object' && value !== null && !Array.isArray(value); }
function isIsoDate(value: string): boolean { const date = /^([0-9]{4})-([0-9]{2})-([0-9]{2})$/.exec(value); if (!date) return false; const parsed = new Date(`${value}T00:00:00Z`); return parsed.getUTCFullYear() === Number(date[1]) && parsed.getUTCMonth() + 1 === Number(date[2]) && parsed.getUTCDate() === Number(date[3]); }
function isAllowedUrl(value: string, allowInternal = false): boolean { if (allowInternal && (value.startsWith('/') || value.startsWith('#'))) return !value.includes('..') && !/\s/.test(value); try { const url = new URL(value); return ['http:', 'https:', ...(allowInternal ? ['mailto:'] : [])].includes(url.protocol); } catch { return false; } }
function isPublicImagePath(value: string): boolean { return value.startsWith('/post-images/') && !value.includes('..') && !value.includes('\\') && !/\s/.test(value); }
function positiveInteger(value: unknown, fallback: number, key: string, node: MarkdownNode, state: CompilerState): number | undefined { if (value === undefined) return fallback; if (typeof value !== 'number' || !Number.isInteger(value) || value <= 0) { addDiagnostic(state, node, `Frontmatter '${key}' must be a positive integer.`, 'validation'); return undefined; } return value; }
function booleanValue(value: unknown, fallback: boolean, key: string, node: MarkdownNode, state: CompilerState): boolean | undefined { if (value === undefined) return fallback; if (typeof value !== 'boolean') { addDiagnostic(state, node, `Frontmatter '${key}' must be a boolean.`, 'validation'); return undefined; } return value; }
function pascalCase(slug: string): string { return slug.split('-').map((part) => part[0].toUpperCase() + part.slice(1)).join(''); }
function formatPrologueDate(date: string): string { const [year, month, day] = date.split('-'); return `${day}.${month}.${year}`; }
function isRoadmapData(value: unknown): value is RoadmapData { if (!isRecord(value) || !Array.isArray(value.items) || (value.title !== undefined && typeof value.title !== 'string') || (value.description !== undefined && typeof value.description !== 'string')) return false; return value.items.every(isRoadmapItem); }
function isRoadmapItem(value: unknown): value is RoadmapItem { return isRecord(value) && typeof value.version === 'string' && typeof value.description === 'string' && optionalStringArray(value.features) && optionalStringArray(value.bugfixes) && optionalBoolean(value.isCurrentRelease) && optionalBoolean(value.isCompleted); }
function optionalStringArray(value: unknown): boolean { return value === undefined || (Array.isArray(value) && value.every((item) => typeof item === 'string')); }
function optionalBoolean(value: unknown): boolean { return value === undefined || typeof value === 'boolean'; }
