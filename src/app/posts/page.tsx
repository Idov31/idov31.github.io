"use client";
import {useEffect, useMemo, useState} from 'react';
import BlogPost from "@/components/BlogViewComponents";
import {blogPosts} from "@/data/blogPosts";

export default function Posts() {
    const postsPerPage = 6;
    const [currentPage, setCurrentPage] = useState(1);

    const totalPages = Math.ceil(blogPosts.length / postsPerPage);

    const currentPosts = useMemo(
        () => blogPosts.slice((currentPage - 1) * postsPerPage, currentPage * postsPerPage),
        [currentPage, postsPerPage],
    );
    useEffect(() => { document.title = "Ido Veltzman :: Posts"; }, []);

    return (
        <div className="animate-fade-in">
            {/* Page header */}
            <div className="mb-8">
                <div className="badge badge-purple mb-3">Articles</div>
                <h1 className="text-4xl font-bold text-txtHeader">Articles</h1>
            </div>

            {/* Post list */}
            <div className="space-y-4">
                {currentPosts.map(post => (
                    <BlogPost key={post.href} {...post} />
                ))}
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
                <div className="flex items-center justify-center gap-2 mt-10">
                    {Array.from({length: totalPages}, (_, i) => i + 1).map(pageNumber => (
                        <button
                            key={pageNumber}
                            onClick={() => setCurrentPage(pageNumber)}
                            className={`w-9 h-9 rounded-lg text-sm font-medium transition-all duration-200
                                ${currentPage === pageNumber
                                    ? 'bg-accentPurple text-white shadow-glow'
                                    : 'text-txtMuted hover:text-txtRegular hover:bg-white/5 border border-borderSubtle'
                                }`}
                        >
                            {pageNumber}
                        </button>
                    ))}
                </div>
            )}
        </div>
    );
}
