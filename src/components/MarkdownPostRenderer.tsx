"use client";

import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { BlogPrologue } from "@/components/BlogComponents";
import TableOfContents from "@/components/TableOfContents";
import MarkdownComponents from "@/components/MarkdownComponents";
import type { PostFrontmatter } from "@/lib/markdown";

interface MarkdownPostRendererProps {
    frontmatter: PostFrontmatter;
    content: string;
}

export default function MarkdownPostRenderer({
    frontmatter,
    content,
}: MarkdownPostRendererProps) {
    return (
        <div className="card-surface rounded-xl p-6 lg:p-8 animate-fade-in post-content">
            <BlogPrologue
                title={frontmatter.title}
                date={frontmatter.date}
                projectLink={frontmatter.projectLink}
            />
            <div className="pt-4">
                <article>
                    <TableOfContents />
                    <ReactMarkdown
                        remarkPlugins={[remarkGfm]}
                        components={MarkdownComponents}
                    >
                        {content}
                    </ReactMarkdown>
                </article>
            </div>
        </div>
    );
}
