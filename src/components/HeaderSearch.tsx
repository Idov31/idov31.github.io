"use client";

import {FormEvent, useEffect, useMemo, useRef, useState} from "react";
import Link from "next/link";
import {useRouter} from "next/navigation";
import {blogPosts} from "@/data/blogPosts";

type HeaderSearchProps = {
    onResultClick?: () => void;
    autoFocus?: boolean;
    showAllPostsWhenEmpty?: boolean;
};

let cachedFullPostText: Record<string, string> | null = null;
let fullPostTextPromise: Promise<Record<string, string>> | null = null;

async function loadFullPostText() {
    if (cachedFullPostText) {
        return cachedFullPostText;
    }

    if (fullPostTextPromise) {
        return fullPostTextPromise;
    }

    fullPostTextPromise = Promise.all(
        blogPosts.map(async (post) => {
            try {
                const response = await fetch(post.href, {credentials: "same-origin"});

                if (!response.ok) {
                    throw new Error(`Failed to fetch ${post.href}`);
                }

                const html = await response.text();
                const documentFragment = new DOMParser().parseFromString(html, "text/html");
                const articleRoot = documentFragment.querySelector(".post-content") ?? documentFragment.querySelector("main");
                const fullText = articleRoot?.textContent?.replace(/\s+/g, " ").trim() ?? "";

                return [post.href, fullText] as const;
            } catch {
                return [post.href, `${post.headerContent} ${post.postContent}`] as const;
            }
        }),
    ).then((entries) => {
        cachedFullPostText = Object.fromEntries(entries);
        return cachedFullPostText;
    }).finally(() => {
        fullPostTextPromise = null;
    });

    return fullPostTextPromise;
}

function SearchIcon() {
    return (
        <svg
            viewBox="0 0 24 24"
            width="16"
            height="16"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
        >
            <circle cx="11" cy="11" r="8"/>
            <path d="m21 21-4.35-4.35"/>
        </svg>
    );
}

export default function HeaderSearch({
    onResultClick,
    autoFocus = false,
    showAllPostsWhenEmpty = false,
}: HeaderSearchProps) {
    const router = useRouter();
    const inputRef = useRef<HTMLInputElement>(null);
    const [query, setQuery] = useState("");
    const [fullPostText, setFullPostText] = useState<Record<string, string> | null>(cachedFullPostText);
    const [isIndexingPosts, setIsIndexingPosts] = useState(false);

    const trimmedQuery = query.trim();

    const ensureFullPostText = async () => {
        if (fullPostText || isIndexingPosts) {
            return;
        }

        setIsIndexingPosts(true);

        try {
            const loadedText = await loadFullPostText();
            setFullPostText(loadedText);
        } finally {
            setIsIndexingPosts(false);
        }
    };

    const results = useMemo(() => {
        const words = trimmedQuery.toLowerCase().split(/\s+/).filter(Boolean);

        if (words.length === 0) {
            return [];
        }

        return blogPosts.filter((post) => {
            const searchableText = (fullPostText?.[post.href] ?? `${post.headerContent} ${post.postContent}`).toLowerCase();
            return words.every((word) => searchableText.includes(word));
        }).slice(0, 6);
    }, [fullPostText, trimmedQuery]);

    const visiblePosts = useMemo(() => {
        if (trimmedQuery.length > 0) {
            return results;
        }

        if (!showAllPostsWhenEmpty) {
            return [];
        }

        return blogPosts;
    }, [results, showAllPostsWhenEmpty, trimmedQuery]);

    useEffect(() => {
        if (autoFocus) {
            inputRef.current?.focus();
        }
    }, [autoFocus]);

    const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
        event.preventDefault();

        if (results.length === 0) {
            return;
        }

        router.push(results[0].href);
        setQuery("");
        onResultClick?.();
    };

    const showResults = visiblePosts.length > 0;

    return (
        <div className="w-full overflow-hidden rounded-2xl border border-borderSubtle bg-bgInsideDiv shadow-[0_16px_48px_rgba(15,23,42,0.16)] backdrop-blur-xl">
            <form onSubmit={handleSubmit} className="relative border-b border-borderSubtle/80 p-3">
                <span className="pointer-events-none absolute left-6 top-1/2 -translate-y-1/2 text-txtMuted">
                    <SearchIcon/>
                </span>
                <input
                    ref={inputRef}
                    type="search"
                    value={query}
                    onChange={(event) => {
                        setQuery(event.target.value);
                        void ensureFullPostText();
                    }}
                    onFocus={() => {
                        void ensureFullPostText();
                    }}
                    placeholder="Search posts"
                    aria-label="Search blog posts"
                    className="h-11 w-full rounded-xl border border-borderSubtle bg-bgRegular/70 pl-10 pr-4 text-sm text-txtRegular placeholder:text-txtMuted outline-none transition-all duration-200 focus:border-accentPurple/60 focus:ring-2 focus:ring-accentPurple/20"
                />
            </form>

            {isIndexingPosts ? (
                <div className="px-4 py-4 text-sm text-txtMuted">
                    Searching full post content...
                </div>
            ) : showResults ? (
                <div className="max-h-96 overflow-y-auto p-2">
                    {visiblePosts.map((post) => (
                        <Link
                            key={post.href}
                            href={post.href}
                            onClick={() => {
                                setQuery("");
                                onResultClick?.();
                            }}
                            className="block rounded-xl px-4 py-3 transition-colors duration-200 hover:bg-[var(--nav-hover-bg)]"
                        >
                            <div className="flex items-start justify-between gap-3">
                                <div className="min-w-0">
                                    <p className="text-sm font-semibold text-txtHeader line-clamp-1">{post.headerContent}</p>
                                    <p className="mt-1 text-xs leading-relaxed text-txtMuted line-clamp-2">{post.postContent}</p>
                                </div>
                                <span className="badge badge-purple shrink-0 whitespace-nowrap text-[11px]">{post.subHeaderContent}</span>
                            </div>
                        </Link>
                    ))}
                </div>
            ) : trimmedQuery.length > 0 ? (
                <div className="px-4 py-4 text-sm text-txtMuted">
                    No posts match those terms.
                </div>
            ) : (
                <div className="px-4 py-4 text-sm text-txtMuted">
                    Search across all blog post content.
                </div>
            )}
        </div>
    );
}