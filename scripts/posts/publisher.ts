import { access, mkdir, readFile, rename, rm, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import ts from 'typescript';

import { compilePost } from './compiler';

const workspaceRoot = path.resolve(process.cwd());
const draftsRoot = path.join(workspaceRoot, 'drafts');
const postsRoot = path.join(workspaceRoot, 'src', 'app', 'posts');
const publicImagesRoot = path.join(workspaceRoot, 'public', 'post-images');
const indexPath = path.join(workspaceRoot, 'src', 'data', 'blogPosts.ts');

export type PublishDiagnostic = {
    message: string;
    source?: string;
};

export type PublishResult = {
    diagnostics: PublishDiagnostic[];
    published: boolean;
};

type CompiledPost = {
    frontmatter: {
        slug: string;
        date: string;
        title: string;
        summary: string;
        cardImage: string;
        cardImageAlt: string;
        cardImageWidth?: number;
        cardImageHeight?: number;
        sub?: boolean;
    };
    generatedTsx: string;
    diagnostics: Array<{ message?: string; reason?: string; source?: string; line?: number; column?: number }>;
};

type StagedWrite = {
    target: string;
    temporary: string;
    original: string | undefined;
};

function isInside(candidate: string, root: string): boolean {
    const relative = path.relative(root, candidate);
    return relative !== '' && !relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative);
}

function diagnostic(message: string, source?: string): PublishDiagnostic {
    return { message, source };
}

function formatCompilerDiagnostics(diagnostics: CompiledPost['diagnostics'], sourcePath: string): PublishDiagnostic[] {
    return diagnostics.map((entry) => {
        const position = entry.line === undefined ? '' : `:${entry.line}${entry.column === undefined ? '' : `:${entry.column}`}`;
        return diagnostic(entry.message ?? entry.reason ?? 'Markdown compilation failed.', `${entry.source ?? sourcePath}${position}`);
    });
}

function assertDraftPath(input: string): string | PublishDiagnostic {
    const resolved = path.resolve(workspaceRoot, input);
    if (path.extname(resolved).toLowerCase() !== '.md') {
        return diagnostic('The input file must have a .md extension.', input);
    }

    if (!isInside(resolved, draftsRoot)) {
        return diagnostic('The input Markdown file must be located beneath drafts/.', input);
    }

    return resolved;
}

async function fileExists(filePath: string): Promise<boolean> {
    try {
        await access(filePath);
        return (await stat(filePath)).isFile();
    } catch {
        return false;
    }
}

function publicImagePath(value: string): string | PublishDiagnostic {
    if (!value.startsWith('/post-images/')) {
        return diagnostic(`Image path must be root-relative beneath /post-images/: ${value}`);
    }

    let decoded: string;
    try {
        decoded = decodeURIComponent(value);
    } catch {
        return diagnostic(`Image path is not valid URI text: ${value}`);
    }
    const candidate = path.resolve(workspaceRoot, 'public', `.${decoded}`);
    if (!isInside(candidate, publicImagesRoot)) {
        return diagnostic(`Image path escapes public/post-images/: ${value}`);
    }

    return candidate;
}

function findGeneratedImagePaths(generatedTsx: string): string[] {
    const matches = generatedTsx.matchAll(/['"](\/post-images\/[A-Za-z0-9._~!$&'()*+,;=:@%\-/]+)['"]/g);
    return Array.from(new Set(Array.from(matches, (match) => match[1])));
}

async function validateImages(compiled: CompiledPost): Promise<PublishDiagnostic[]> {
    const imagePaths = new Set([compiled.frontmatter.cardImage, ...findGeneratedImagePaths(compiled.generatedTsx)]);
    const diagnostics: PublishDiagnostic[] = [];

    for (const imagePath of Array.from(imagePaths)) {
        const resolved = publicImagePath(imagePath);
        if (typeof resolved !== 'string') {
            diagnostics.push(resolved);
        } else if (!(await fileExists(resolved))) {
            diagnostics.push(diagnostic(`Referenced image does not exist: ${imagePath}`));
        }
    }

    return diagnostics;
}

function literalString(property: ts.PropertyAssignment, sourceFile: ts.SourceFile): string | undefined {
    const initializer = property.initializer;
    if (ts.isStringLiteral(initializer) || ts.isNoSubstitutionTemplateLiteral(initializer)) {
        return initializer.text;
    }

    return undefined;
}

function literalNumber(property: ts.PropertyAssignment): number | undefined {
    return ts.isNumericLiteral(property.initializer) ? Number(property.initializer.text) : undefined;
}

function literalBoolean(property: ts.PropertyAssignment): boolean | undefined {
    return property.initializer.kind === ts.SyntaxKind.TrueKeyword ? true : property.initializer.kind === ts.SyntaxKind.FalseKeyword ? false : undefined;
}

function propertyName(property: ts.ObjectLiteralElementLike): string | undefined {
    if (!ts.isPropertyAssignment(property) || property.name === undefined) {
        return undefined;
    }

    if (ts.isIdentifier(property.name) || ts.isStringLiteral(property.name)) {
        return property.name.text;
    }

    return undefined;
}

type BlogEntry = {
    href: string;
    date: Date;
    node: ts.ObjectLiteralExpression;
};

type BlogIndex = {
    source: string;
    array: ts.ArrayLiteralExpression;
    sourceFile: ts.SourceFile;
    entries: BlogEntry[];
};

function parseIndex(source: string): BlogIndex | PublishDiagnostic {
    const sourceFile = ts.createSourceFile(indexPath, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
    let declaration: ts.VariableDeclaration | undefined;
    let declarations = 0;

    sourceFile.forEachChild((statement) => {
        if (!ts.isVariableStatement(statement) || !statement.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword)) return;
        for (const item of statement.declarationList.declarations) {
            if (ts.isIdentifier(item.name) && item.name.text === 'blogPosts') {
                declarations += 1;
                declaration = item;
            }
        }
    });

    if (declarations !== 1 || !declaration?.initializer || !ts.isArrayLiteralExpression(declaration.initializer)) {
        return diagnostic('src/data/blogPosts.ts must export a static blogPosts array.');
    }

    const requiredProperties = new Set(['href', 'headerContent', 'subHeaderContent', 'imagePath', 'imageAlt', 'imageWidth', 'imageHeight', 'postContent']);
    const allowedProperties = new Set([...Array.from(requiredProperties), 'sub']);
    const entries: BlogEntry[] = [];
    for (const element of declaration.initializer.elements) {
        if (!ts.isObjectLiteralExpression(element)) {
            return diagnostic('blogPosts must contain only static object literals.');
        }

        const properties = new Map<string, ts.PropertyAssignment>();
        for (const property of element.properties) {
            const name = propertyName(property);
            if (!name || !ts.isPropertyAssignment(property) || properties.has(name)) {
                return diagnostic('blogPosts entries must contain unique, static properties only.');
            }
            if (!allowedProperties.has(name)) return diagnostic(`blogPosts contains unsupported property '${name}'.`);
            properties.set(name, property);
        }

        if (!Array.from(requiredProperties).every((name) => properties.has(name))) {
            return diagnostic('blogPosts entries are missing required static properties.');
        }

        const href = literalString(properties.get('href')!, sourceFile);
        const dateText = literalString(properties.get('subHeaderContent')!, sourceFile);
        const textProperties = ['headerContent', 'imagePath', 'imageAlt', 'postContent'];
        if (!href || !dateText || !href.startsWith('/posts/') || textProperties.some((name) => literalString(properties.get(name)!, sourceFile) === undefined) || literalNumber(properties.get('imageWidth')!) === undefined || literalNumber(properties.get('imageHeight')!) === undefined || (properties.has('sub') && literalBoolean(properties.get('sub')!) === undefined)) {
            return diagnostic('blogPosts entries must use static literal values with the expected shape.');
        }

        const date = parseBlogDate(dateText);
        if (!date) {
            return diagnostic(`blogPosts contains an unparseable date: ${dateText}`);
        }
        entries.push({ href, date, node: element });
    }

    return { source, sourceFile, array: declaration.initializer, entries };
}

function formatDate(isoDate: string): string {
    const date = new Date(`${isoDate}T00:00:00.000Z`);
    return new Intl.DateTimeFormat('en-GB', { day: '2-digit', month: 'short', year: 'numeric', timeZone: 'UTC' }).format(date);
}

function parseBlogDate(dateText: string): Date | undefined {
    const match = /^(\d{2}) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (\d{4})$/.exec(dateText);
    if (!match) return undefined;
    const month = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'].indexOf(match[2]);
    const date = new Date(Date.UTC(Number(match[3]), month, Number(match[1])));
    return date.getUTCFullYear() === Number(match[3]) && date.getUTCMonth() === month && date.getUTCDate() === Number(match[1]) ? date : undefined;
}

function makeEntry(compiled: CompiledPost): string {
    const { frontmatter } = compiled;
    const quote = (value: string): string => JSON.stringify(value);
    return [
        '    {',
        `        href: ${quote(`/posts/${frontmatter.slug}`)},`,
        `        headerContent: ${quote(frontmatter.title)},`,
        `        subHeaderContent: ${quote(formatDate(frontmatter.date))},`,
        `        imagePath: ${quote(frontmatter.cardImage)},`,
        `        imageAlt: ${quote(frontmatter.cardImageAlt)},`,
        `        imageWidth: ${frontmatter.cardImageWidth ?? 135},`,
        `        imageHeight: ${frontmatter.cardImageHeight ?? 51},`,
        `        postContent: ${quote(frontmatter.summary)},`,
        ...(frontmatter.sub === undefined ? [] : [`        sub: ${frontmatter.sub}`]),
        '    }',
    ].join('\n');
}

function updateIndex(index: BlogIndex, compiled: CompiledPost): string | PublishDiagnostic {
    const newEntry = makeEntry(compiled);
    const href = `/posts/${compiled.frontmatter.slug}`;
    const matching = index.entries.filter((entry) => entry.href === href);
    if (matching.length > 1) return diagnostic(`blogPosts has duplicate entries for ${href}.`);

    if (matching.length === 1) {
        const match = matching[0];
        return `${index.source.slice(0, match.node.getStart(index.sourceFile))}${newEntry}${index.source.slice(match.node.getEnd())}`;
    }

    const newDate = new Date(`${compiled.frontmatter.date}T00:00:00.000Z`);
    if (Number.isNaN(newDate.getTime())) return diagnostic(`Invalid frontmatter date: ${compiled.frontmatter.date}`);
    const insertionIndex = index.entries.findIndex((entry) => newDate.getTime() > entry.date.getTime());
    if (insertionIndex >= 0) {
        const target = index.entries[insertionIndex].node;
        return `${index.source.slice(0, target.getFullStart())}\n${newEntry},${index.source.slice(target.getFullStart())}`;
    }

    const closingBracket = index.array.getEnd() - 1;
    const beforeClosing = index.source.slice(0, closingBracket);
    return `${beforeClosing}${newEntry},\n${index.source.slice(closingBracket)}`;
}

async function stageWrite(target: string, content: string): Promise<StagedWrite> {
    const original = (await fileExists(target)) ? await readFile(target, 'utf8') : undefined;
    await mkdir(path.dirname(target), { recursive: true });
    const temporary = path.join(path.dirname(target), `.${path.basename(target)}.${process.pid}.${Date.now()}.tmp`);
    await writeFile(temporary, content, 'utf8');
    return { target, temporary, original };
}

async function commitStagedWrites(stagedWrites: StagedWrite[]): Promise<void> {
    const committed: StagedWrite[] = [];
    try {
        for (const staged of stagedWrites) {
            await rename(staged.temporary, staged.target);
            committed.push(staged);
        }
    } catch (error) {
        for (const staged of committed.reverse()) {
            if (staged.original === undefined) {
                await rm(staged.target, { force: true });
            } else {
                await writeFile(staged.target, staged.original, 'utf8');
            }
        }
        throw error;
    } finally {
        await Promise.all(stagedWrites.map((staged) => rm(staged.temporary, { force: true })));
    }
}

async function prepare(input: string): Promise<{ compiled: CompiledPost; pagePath: string; indexContent: string } | PublishResult> {
    const draftPath = assertDraftPath(input);
    if (typeof draftPath !== 'string') return { diagnostics: [draftPath], published: false };
    if (!(await fileExists(draftPath))) return { diagnostics: [diagnostic('Draft file does not exist.', input)], published: false };

    const markdown = await readFile(draftPath, 'utf8');
    const compiled = compilePost(markdown, draftPath) as CompiledPost;
    if (compiled.diagnostics.length > 0) return { diagnostics: formatCompilerDiagnostics(compiled.diagnostics, draftPath), published: false };
    if (!compiled.frontmatter || typeof compiled.generatedTsx !== 'string') {
        return { diagnostics: [diagnostic('Compiler returned no generated page for an otherwise valid draft.')], published: false };
    }

    const imageDiagnostics = await validateImages(compiled);
    if (imageDiagnostics.length > 0) return { diagnostics: imageDiagnostics, published: false };

    const pagePath = path.join(postsRoot, compiled.frontmatter.slug, 'page.tsx');
    if (!isInside(pagePath, postsRoot)) return { diagnostics: [diagnostic('Compiled slug resolves outside src/app/posts/.')], published: false };

    if (!(await fileExists(indexPath))) return { diagnostics: [diagnostic('src/data/blogPosts.ts does not exist.')], published: false };
    const parsedIndex = parseIndex(await readFile(indexPath, 'utf8'));
    if (!('array' in parsedIndex)) return { diagnostics: [parsedIndex], published: false };
    const indexContent = updateIndex(parsedIndex, compiled);
    if (typeof indexContent !== 'string') return { diagnostics: [indexContent], published: false };

    return { compiled, pagePath, indexContent };
}

export async function checkDraft(input: string): Promise<PublishResult> {
    const prepared = await prepare(input);
    return 'diagnostics' in prepared ? prepared : { diagnostics: [], published: false };
}

export async function publishDraft(input: string): Promise<PublishResult> {
    const prepared = await prepare(input);
    if ('diagnostics' in prepared) return prepared;

    try {
        const staged = await Promise.all([
            stageWrite(prepared.pagePath, prepared.compiled.generatedTsx),
            stageWrite(indexPath, prepared.indexContent),
        ]);
        await commitStagedWrites(staged);
        return { diagnostics: [], published: true };
    } catch (error) {
        return { diagnostics: [diagnostic(error instanceof Error ? `Unable to publish draft: ${error.message}` : 'Unable to publish draft.')], published: false };
    }
}
