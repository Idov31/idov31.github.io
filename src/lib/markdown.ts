import fs from "fs";
import path from "path";
import matter from "gray-matter";

const postsDirectory = path.join(process.cwd(), "src/content/posts");

export interface PostFrontmatter {
    title: string;
    date: string;
    description: string;
    projectLink?: string;
    imagePath?: string;
    imageAlt?: string;
    imageWidth?: number;
    imageHeight?: number;
    tags?: string[];
}

export interface MarkdownPost {
    slug: string;
    frontmatter: PostFrontmatter;
    content: string;
}

export function getMarkdownPostSlugs(): string[] {
    if (!fs.existsSync(postsDirectory)) return [];
    return fs
        .readdirSync(postsDirectory)
        .filter((file) => file.endsWith(".md"))
        .map((file) => file.replace(/\.md$/, ""));
}

export function getMarkdownPost(slug: string): MarkdownPost | null {
    const fullPath = path.join(postsDirectory, `${slug}.md`);
    if (!fs.existsSync(fullPath)) return null;

    const fileContents = fs.readFileSync(fullPath, "utf8");
    const { data, content } = matter(fileContents);

    return {
        slug,
        frontmatter: data as PostFrontmatter,
        content,
    };
}

export function getAllMarkdownPosts(): MarkdownPost[] {
    return getMarkdownPostSlugs()
        .map((slug) => getMarkdownPost(slug))
        .filter(Boolean) as MarkdownPost[];
}

/**
 * Returns BlogPostSummary-compatible objects for all markdown posts so they
 * can be merged into the existing static `blogPosts` array on the /posts page.
 */
export function getMarkdownPostSummaries() {
    return getAllMarkdownPosts().map((post) => ({
        href: `/posts/${post.slug}`,
        headerContent: post.frontmatter.title,
        subHeaderContent: post.frontmatter.date,
        imagePath: post.frontmatter.imagePath ?? "",
        imageAlt: post.frontmatter.imageAlt ?? post.frontmatter.title,
        imageWidth: post.frontmatter.imageWidth ?? 135,
        imageHeight: post.frontmatter.imageHeight ?? 51,
        postContent: post.frontmatter.description,
    }));
}
