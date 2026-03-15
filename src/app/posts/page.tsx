"use client";
import {useCallback, useEffect, useMemo, useState} from 'react';
import BlogPost from "@/components/BlogViewComponents";

type BlogPostType = {
    href: string;
    headerContent: string;
    subHeaderContent: string;
    imagePath: string;
    imageAlt: string;
    imageWidth: number;
    imageHeight: number;
    postContent: string;
    sub?: boolean;
};

export default function Posts() {
    const postsPerPage = 6;
    const [currentPage, setCurrentPage] = useState(1);
    const [currentPosts, setCurrentPosts] = useState<BlogPostType[]>([]);

    const blogPosts = useMemo(() => [
        {
            href: "/posts/lord-of-the-ring0-p6",
            headerContent: "Lord Of The Ring0 \u2014 Part 6 | Conclusion",
            subHeaderContent: "31 Mar 2024",
            imagePath: "/post-images/lotr06.png",
            imageAlt: "lotr06",
            imageWidth: 135,
            imageHeight: 51,
            postContent: "In the last blog post, we learned about two common hooking methods (IRP Hooking and SSDT " +
                "Hooking) and two different injection techniques from the kernel to the user mode for both shellcode " +
                "and DLL (APC and CreateThread). In this post we write a simple driver capable of bypassing AMSI to " +
                "demonstrate patching usermode memory from the kernel.",
            sub: false
        },
        {
            href: "/posts/lord-of-the-ring0-p5",
            headerContent: "Lord Of The Ring0 \u2014 Part 5 | Saruman's Manipulation",
            subHeaderContent: "19 Jul 2023",
            imagePath: "/post-images/lotr05.png",
            imageAlt: "lotr05",
            imageWidth: 135,
            imageHeight: 51,
            postContent: "In the last blog post, we learned about the different types of kernel callbacks and " +
                "created our registry protector driver. In this post, two common hooking methods " +
                "(IRP Hooking and SSDT Hooking) and two different injection techniques are explained."
        },
        {
            href: "/posts/lord-of-the-ring0-p4",
            headerContent: "Lord Of The Ring0 \u2014 Part 4 | The Call Back Home",
            subHeaderContent: "24 Feb 2023",
            imagePath: "/post-images/lotr04.png",
            imageAlt: "lotr04",
            imageWidth: 135,
            imageHeight: 51,
            postContent: "In the last blog post, we learned some debugging concepts, understood IOCTLs, and started " +
                "to learn how to validate data from user mode. In this post, the different types of callbacks " +
                "are explained."
        },
        {
            href: "/posts/cronos-sleep-obfuscation",
            headerContent: "timeout /t 31 && start evil.exe",
            subHeaderContent: "06 Nov 2022",
            imagePath: "/post-images/cronos-sleep-obf.png",
            imageAlt: "cronos-sleep-obf",
            imageWidth: 135,
            imageHeight: 51,
            postContent: "Cronos is a new sleep obfuscation technique co-authored by idov31 and yxel. It encrypts " +
                "the process image with RC4 encryption and evades memory scanners by changing memory regions " +
                "permissions from RWX to RW back and forth."
        },
        {
            href: "/posts/lord-of-the-ring0-p3",
            headerContent: "Lord Of The Ring0 \u2014 Part 3 | Sailing to the Land of the User",
            subHeaderContent: "30 Oct 2022",
            imagePath: "/post-images/lotr03.png",
            imageAlt: "lotr03",
            imageWidth: 135,
            imageHeight: 51,
            postContent: "In the last blog post, we understood callback routines and created a driver that can block " +
                "access to a certain process. In this post, we dive into debugging and cross-boundary communication."
        },
        {
            href: "/posts/lord-of-the-ring0-p2",
            headerContent: "Lord Of The Ring0 \u2014 Part 2 | A Tale of Routines, IOCTLs and IRPs",
            subHeaderContent: "04 Aug 2022",
            imagePath: "/post-images/lotr02.png",
            imageAlt: "lotr02",
            imageWidth: 135,
            imageHeight: 51,
            postContent: "In the last blog post, we had an introduction to kernel development. In this post, more " +
                "about callbacks, how to start writing a rootkit, and the difficulties encountered during " +
                "the development of Nidhogg."
        },
        {
            href: "/posts/lord-of-the-ring0-p1",
            headerContent: "Lord Of The Ring0 \u2014 Part 1 | Introduction",
            subHeaderContent: "14 Jul 2022",
            imagePath: "/post-images/lotr0.png",
            imageAlt: "lotr01",
            imageWidth: 135,
            imageHeight: 51,
            postContent: "This blog post series is a journey documenting the development of Nidhogg. It covers " +
                "difficulties encountered while developing a stable kernel mode driver in 2022 and tips & tricks " +
                "for everyone who wants to start."
        },
        {
            href: "/posts/rust101-rustomware",
            headerContent: "Rust 101 \u2014 Let's Write Rustomware",
            subHeaderContent: "07 May 2022",
            imagePath: "/post-images/rustsomware.png",
            imageAlt: "rustsomware",
            imageWidth: 135,
            imageHeight: 51,
            postContent: "When I first heard about Rust, my reaction was \"Why?\". The language looked like a " +
                "\"wannabe\" C. After reading more about it, I decided to challenge myself by writing rustomware."
        },
        {
            href: "/posts/function-stomping",
            headerContent: "The Good, The Bad and The Stomped Function",
            subHeaderContent: "28 Jan 2022",
            imagePath: "/post-images/function-stomping.png",
            imageAlt: "function-stomping",
            imageWidth: 135,
            imageHeight: 51,
            postContent: "When I first heard about ModuleStomping I was charmed since it wasn't like any other " +
                "known injection method. Instead of allocating new space in the process, it does something " +
                "entirely different."
        },
        {
            href: "/posts/list-udp-connections",
            headerContent: "UdpInspector \u2014 Getting Active UDP Connections Without Sniffing",
            subHeaderContent: "19 Aug 2021",
            imagePath: "/post-images/udpinspect.png",
            imageAlt: "udpinspect",
            imageWidth: 135,
            imageHeight: 51,
            postContent: "Many times I've wondered how comes that there are no tools to get active UDP connections " +
                "without sniffing. That is the point that I went on a quest to investigate the matter."
        },
    ], []);

    const totalPages = Math.ceil(blogPosts.length / postsPerPage);

    const handlePageClick = useCallback((pageNumber: number) => {
        if (pageNumber !== currentPage) {
            setCurrentPage(pageNumber);
        }
    }, [currentPage]);

    useEffect(() => {
        const newCurrentPosts = blogPosts.slice((currentPage - 1) * postsPerPage, currentPage * postsPerPage);
        setCurrentPosts(newCurrentPosts);
    }, [currentPage, handlePageClick, blogPosts]);

    return (
        <div className="animate-fade-in">
            {/* Page header */}
            <div className="mb-8">
                <div className="badge badge-purple mb-3">Blog</div>
                <h1 className="text-4xl font-bold text-txtHeader">Posts</h1>
                <p className="text-txtMuted mt-2">
                    {blogPosts.length} articles on security research, kernel development, and more.
                </p>
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
                            onClick={() => handlePageClick(pageNumber)}
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
