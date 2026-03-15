import { notFound } from "next/navigation";
import MarkdownPostRenderer from "@/components/MarkdownPostRenderer";
import { getMarkdownPost, getMarkdownPostSlugs } from "@/lib/markdown";

interface Props {
    params: { slug: string };
}

/**
 * Pre-render a page for every .md file found in src/content/posts/.
 * Existing posts that have their own static page.tsx take precedence over this
 * dynamic route, so nothing changes for those posts.
 */
export function generateStaticParams() {
    return getMarkdownPostSlugs().map((slug) => ({ slug }));
}

export default function MarkdownPostPage({ params }: Props) {
    const post = getMarkdownPost(params.slug);

    if (!post) {
        notFound();
    }

    return (
        <MarkdownPostRenderer
            frontmatter={post.frontmatter}
            content={post.content}
        />
    );
}
