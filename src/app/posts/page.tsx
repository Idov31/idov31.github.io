"use client";
import {useCallback, useEffect, useState} from 'react';
import Image from 'next/image';
import Link from 'next/link';

type BlogPostType = {
    href: string;
    headerContent: string;
    subHeaderContent: string;
    imagePath: string;
    imageAlt: string;
    postContent: string;
    tags?: string[];
};

const blogPosts: BlogPostType[] = [
    {
        href: "/posts/lord-of-the-ring0-p6",
        headerContent: "Lord Of The Ring0 - Part 6 | Conclusion",
        subHeaderContent: "Ido Veltzman · 31.03.2024",
        imagePath: "/post-images/lotr06.png",
        imageAlt: "Lord Of The Ring0 Part 6",
        postContent: "In this final installment, we write a driver capable of bypassing AMSI to demonstrate patching usermode memory from the kernel — tying together everything learned throughout the series.",
        tags: ["Kernel", "AMSI", "Drivers"],
    },
    {
        href: "/posts/lord-of-the-ring0-p5",
        headerContent: "Lord Of The Ring0 - Part 5 | Saruman's Manipulation",
        subHeaderContent: "Ido Veltzman · 19.07.2023",
        imagePath: "/post-images/lotr05.png",
        imageAlt: "Lord Of The Ring0 Part 5",
        postContent: "Covering two common hooking methods (IRP Hooking and SSDT Hooking) and two injection techniques from kernel to user mode for shellcode and DLL injection (APC and CreateThread).",
        tags: ["Kernel", "Hooking", "Injection"],
    },
    {
        href: "/posts/lord-of-the-ring0-p4",
        headerContent: "Lord Of The Ring0 - Part 4 | The Call Back Home",
        subHeaderContent: "Ido Veltzman · 24.02.2023",
        imagePath: "/post-images/lotr04.png",
        imageAlt: "Lord Of The Ring0 Part 4",
        postContent: "Deep-diving into kernel callbacks: process, thread, image-load, and registry callbacks with practical examples and defensive use cases.",
        tags: ["Kernel", "Callbacks"],
    },
    {
        href: "/posts/cronos-sleep-obfuscation",
        headerContent: "timeout /t 31 && start evil.exe",
        subHeaderContent: "Ido Veltzman · 06.11.2022",
        imagePath: "/post-images/cronos-sleep-obf.png",
        imageAlt: "Cronos Sleep Obfuscation",
        postContent: "Cronos is a sleep obfuscation technique that encrypts the process image with RC4 and evades memory scanners by toggling memory regions between RWX and RW during sleep.",
        tags: ["Evasion", "Sleep Obfuscation"],
    },
    {
        href: "/posts/lord-of-the-ring0-p3",
        headerContent: "Lord Of The Ring0 - Part 3 | Sailing to the Land of the User",
        subHeaderContent: "Ido Veltzman · 30.10.2022",
        imagePath: "/post-images/lotr03.png",
        imageAlt: "Lord Of The Ring0 Part 3",
        postContent: "A deep dive into kernel-to-user mode communication, IOCTL handling, and essential driver debugging techniques to keep your kernel development sane.",
        tags: ["Kernel", "Debugging", "IOCTL"],
    },
    {
        href: "/posts/lord-of-the-ring0-p2",
        headerContent: "Lord Of The Ring0 - Part 2 | A Tale of Routines, IOCTLs and IRPs",
        subHeaderContent: "Ido Veltzman · 04.08.2022",
        imagePath: "/post-images/lotr02.png",
        imageAlt: "Lord Of The Ring0 Part 2",
        postContent: "Covering callbacks, IOCTL handling, IRP management, and the early lessons from building Nidhogg — a feature-rich Windows kernel rootkit.",
        tags: ["Kernel", "IRP", "Rootkit"],
    },
    {
        href: "/posts/lord-of-the-ring0-p1",
        headerContent: "Lord Of The Ring0 - Part 1 | Introduction",
        subHeaderContent: "Ido Veltzman · 14.07.2022",
        imagePath: "/post-images/lotr0.png",
        imageAlt: "Lord Of The Ring0 Part 1",
        postContent: "An introduction to Windows kernel driver development — covering driver structure, test signing, debugging basics, and why kernel development matters for both red and blue teams.",
        tags: ["Kernel", "Intro", "Drivers"],
    },
    {
        href: "/posts/rust101-rustomware",
        headerContent: "Rust 101 — Let's Write Rustomware",
        subHeaderContent: "Ido Veltzman · 07.05.2022",
        imagePath: "/post-images/rustsomware.png",
        imageAlt: "Rust101 Rustomware",
        postContent: "A hands-on journey writing ransomware in Rust — exploring the language's safety guarantees, performance, and how it compares to C in the malware development space.",
        tags: ["Rust", "Malware Dev"],
    },
    {
        href: "/posts/function-stomping",
        headerContent: "The Good, The Bad and The Stomped Function",
        subHeaderContent: "Ido Veltzman · 28.01.2022",
        imagePath: "/post-images/function-stomping.png",
        imageAlt: "Function Stomping",
        postContent: "A look at function stomping — an injection technique that overwrites existing mapped modules instead of allocating new memory, making it far stealthier than classic methods.",
        tags: ["Injection", "Evasion"],
    },
    {
        href: "/posts/list-udp-connections",
        headerContent: "UdpInspector — Getting Active UDP Connections Without Sniffing",
        subHeaderContent: "Ido Veltzman · 19.08.2021",
        imagePath: "/post-images/udpinspect.png",
        imageAlt: "UdpInspector",
        postContent: "An exploration of why Netstat omits UDP connections and how to retrieve them programmatically via the Windows IP Helper API — without packet sniffing.",
        tags: ["Networking", "Windows API"],
    },
];

function PostCard({href, headerContent, subHeaderContent, imagePath, imageAlt, postContent, tags}: BlogPostType) {
    return (
        <Link href={href} className="block group">
            <article className="glass-card p-5 sm:p-6 card-hover h-full flex flex-col gap-4">
                <div className="flex items-start gap-4">
                    <div className="flex-shrink-0 hidden sm:block">
                        <Image
                            src={imagePath}
                            alt={imageAlt}
                            width={100}
                            height={56}
                            className="rounded-lg border border-borderPurple object-cover"
                        />
                    </div>
                    <div className="flex-1 min-w-0">
                        <h2 className="text-lg text-txtHeader font-semibold leading-snug
                                       group-hover:text-txtSubHeader transition-colors duration-200 line-clamp-2">
                            {headerContent}
                        </h2>
                        <p className="text-txtMuted text-xs mt-1">{subHeaderContent}</p>
                    </div>
                </div>
                <p className="text-txtSubHeader text-sm leading-relaxed flex-1 line-clamp-3">
                    {postContent}
                </p>
                <div className="flex flex-wrap gap-2 mt-auto pt-2 border-t border-borderPurple">
                    {tags?.map(tag => (
                        <span key={tag} className="tag-badge">{tag}</span>
                    ))}
                    <span className="ml-auto text-txtLink text-xs group-hover:underline">Read →</span>
                </div>
            </article>
        </Link>
    );
}

export default function Posts() {
    const postsPerPage = 6;
    const [currentPage, setCurrentPage] = useState(1);
    const [currentPosts, setCurrentPosts] = useState<BlogPostType[]>([]);

    const totalPages = Math.ceil(blogPosts.length / postsPerPage);

    const handlePageClick = useCallback((pageNumber: number) => {
        if (pageNumber !== currentPage) {
            setCurrentPage(pageNumber);
            window.scrollTo({top: 0, behavior: 'smooth'});
        }
    }, [currentPage]);

    useEffect(() => {
        setCurrentPosts(blogPosts.slice((currentPage - 1) * postsPerPage, currentPage * postsPerPage));
    }, [currentPage]);

    return (
        <div className="space-y-8 animate-fade-in">
            {/* Header */}
            <div>
                <p className="section-label mb-2">All Posts</p>
                <h1 className="text-3xl sm:text-4xl font-cinzel text-txtHeader">
                    Blog
                </h1>
                <p className="text-txtSubHeader mt-2">
                    Security research, kernel development, and offensive tooling.
                </p>
            </div>

            <div className="terminal-divider"/>

            {/* Post grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                {currentPosts.map(post => (
                    <PostCard key={post.href} {...post} />
                ))}
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
                <div className="flex items-center justify-center gap-2 pt-4">
                    {Array.from({length: totalPages}, (_, i) => i + 1).map(pageNumber => (
                        <button
                            key={pageNumber}
                            onClick={() => handlePageClick(pageNumber)}
                            className={`w-9 h-9 rounded-lg text-sm font-medium transition-all duration-200 ${
                                pageNumber === currentPage
                                    ? 'bg-txtHeader/15 border border-borderPurple text-txtHeader'
                                    : 'text-txtMuted hover:text-txtHeader hover:bg-white/5 border border-transparent'
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
