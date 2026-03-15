"use client";

/**
 * MarkdownComponents
 *
 * Maps standard markdown elements to the site's existing styled components so
 * that blog posts written in plain Markdown are rendered with the same look and
 * feel as the hand-crafted TSX posts.
 *
 * Limitations (cannot be expressed in plain Markdown):
 *  - Code blocks with the collapsible / "Expand" feature — all code is shown
 *    in full. Use the existing TSX post format if you need that feature.
 *  - RoadmapTimeline — no Markdown equivalent.
 */

import React from "react";
import type { Components } from "react-markdown";
import SecondaryHeader, {
    ThirdHeader,
    Code,
    InlineCode,
} from "@/components/BlogComponents";
import BlogImageFigure from "@/components/BlogImageFigure";

const MarkdownComponents: Components = {
    // ── Headings ──────────────────────────────────────────────────────────────
    h2({ children }) {
        return <SecondaryHeader text={String(children)} />;
    },
    h3({ children }) {
        return <ThirdHeader text={String(children)} />;
    },
    h4({ children }) {
        const id = String(children).toLowerCase().replaceAll(" ", "-");
        return (
            <h4 id={id} className="text-lg font-semibold text-txtSubHeader pt-3 pb-1">
                {children}
            </h4>
        );
    },

    // ── Code ──────────────────────────────────────────────────────────────────
    // react-markdown wraps fenced code blocks in <pre><code>. We override
    // both so fenced blocks render as the styled <Code> component and inline
    // snippets render as <InlineCode>.
    pre({ children }) {
        // Remove the <pre> wrapper — the Code component provides its own.
        return <>{children}</>;
    },
    code({ className, children }) {
        const language = className?.replace("language-", "") ?? "";
        const raw = String(children).replace(/\n$/, "");

        // Inline code has no language class and no newlines.
        if (!className && !raw.includes("\n")) {
            return <InlineCode text={raw} />;
        }

        return <Code text={raw} language={language || "text"} />;
    },

    // ── Images ────────────────────────────────────────────────────────────────
    img({ src, alt }) {
        return (
            <BlogImageFigure
                src={src ?? ""}
                alt={alt ?? ""}
                caption={alt ?? undefined}
            />
        );
    },

    // ── Links ─────────────────────────────────────────────────────────────────
    a({ href, children }) {
        return (
            <a
                href={href}
                target={href?.startsWith("http") ? "_blank" : undefined}
                rel={href?.startsWith("http") ? "noopener noreferrer" : undefined}
                className="text-txtLink hover:underline underline-offset-2 transition-colors duration-200"
            >
                {children}
            </a>
        );
    },

    // ── Lists ─────────────────────────────────────────────────────────────────
    ul({ children }) {
        return (
            <ul className="list-none pl-4 pt-4 space-y-2">{children}</ul>
        );
    },
    ol({ children }) {
        return (
            <ol className="list-decimal pl-8 pt-4 space-y-2 marker:text-accentPurple marker:font-mono">
                {children}
            </ol>
        );
    },
    li({ children, ...props }) {
        const isOrdered = (props as { ordered?: boolean }).ordered;
        if (isOrdered) {
            return (
                <li className="text-txtRegular pl-1">{children}</li>
            );
        }
        return (
            <li className="flex gap-2">
                <span className="text-accentPurple mt-1 flex-shrink-0">▸</span>
                <span className="text-txtRegular">{children}</span>
            </li>
        );
    },

    // ── Block elements ────────────────────────────────────────────────────────
    p({ children, node }) {
        // react-markdown wraps standalone images inside a <p>.
        // A <figure> (rendered by BlogImageFigure) cannot be a descendant of <p>,
        // so we unwrap those paragraphs to avoid invalid HTML and hydration errors.
        const hasImageChild = node?.children?.some(
            (child) => child.type === "element" && child.tagName === "img",
        );
        if (hasImageChild) return <>{children}</>;
        return <p className="text-txtRegular pt-4 leading-relaxed">{children}</p>;
    },
    blockquote({ children }) {
        return (
            <blockquote className="border-l-4 border-accentPurple pl-4 italic text-txtMuted my-4">
                {children}
            </blockquote>
        );
    },
    hr() {
        return <div className="divider-glow my-8" />;
    },

    // ── Tables ────────────────────────────────────────────────────────────────
    table({ children }) {
        return (
            <div className="overflow-x-auto my-4">
                <table className="w-full border-collapse">{children}</table>
            </div>
        );
    },
    th({ children }) {
        return (
            <th className="border border-borderSubtle px-4 py-2 bg-bgSurface text-txtSubHeader font-semibold text-left">
                {children}
            </th>
        );
    },
    td({ children }) {
        return (
            <td className="border border-borderSubtle px-4 py-2 text-txtRegular">
                {children}
            </td>
        );
    },

    // ── Inline formatting ─────────────────────────────────────────────────────
    strong({ children }) {
        return <strong className="font-bold text-txtRegular">{children}</strong>;
    },
    em({ children }) {
        return <em className="italic text-txtRegular">{children}</em>;
    },
};

export default MarkdownComponents;
