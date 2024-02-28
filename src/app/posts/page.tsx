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

    const blogPosts = useMemo(() =>[
        {
            href: "/posts/lord-of-the-ring0-p5",
            headerContent: "Lord Of The Ring0 - Part 5 | Saruman's Manipulation",
            subHeaderContent: "Ido Veltzman | 19.07.2023",
            imagePath: "/post-images/lotr05.png",
            imageAlt: "lotr05",
            imageWidth: 135,
            imageHeight: 51,
            postContent: "In the last blog post, we learned about the different types of kernel callbacks and " +
                "created our registry protector driver. In this blog post, I’ll explain two common hooking methods " +
                "(IRP Hooking and SSDT Hooking) and two different injection techniques from the kernel to the user " +
                "mode for both shellcode and DLL (APC and CreateThread) w...",
            sub: false
        },
        {
            href: "/posts/lord-of-the-ring0-p4",
            headerContent: "Lord Of The Ring0 - Part 4 | The call back home",
            subHeaderContent: "Ido Veltzman | 24.02.2023",
            imagePath: "/post-images/lotr04.png",
            imageAlt: "lotr04",
            imageWidth: 135,
            imageHeight: 51,
            postContent: "In the last blog post, we learned some debugging concepts, understood what is IOCTL how to " +
                "handle it and started to learn how to validate the data that we get from the user mode - data that " +
                "cannot be trusted and a handling mistake can cause a blue screen of death. In this blog post, I’ll " +
                "explain the different types of callbacks and we..."
        },
        {
            href: "/posts/cronos-sleep-obfuscation",
            headerContent: "timeout /t 31 && start evil.exe",
            subHeaderContent: "Ido Veltzman | 06.11.2022",
            imagePath: "/post-images/cronos-sleep-obf.png",
            imageAlt: "cronos-sleep-obf",
            imageWidth: 135,
            imageHeight: 51,
            postContent: "Cronos is a new sleep obfuscation technique co-authored by idov31 and yxel. It is based " +
                "on 5pider’s Ekko and like it, it encrypts the process image with RC4 encryption and evades memory " +
                "scanners by also changing memory regions permissions from RWX to RW back and forth. In this blog " +
                "post, we will cover Cronos specifically and sleep ..."
        },
        {
            href: "/posts/lord-of-the-ring0-p3",
            headerContent: "Lord Of The Ring0 - Part 3 | Sailing to the land of the user (and debugging the ship)",
            subHeaderContent: "Ido Veltzman | 30.10.2022",
            imagePath: "/post-images/lotr03.png",
            imageAlt: "lotr03",
            imageWidth: 135,
            imageHeight: 51,
            postContent: "In the last blog post, we understood what it is a callback routine, how to get basic " +
                "information from user mode and for the finale created a driver that can block access to a certain " +
                "process. In this blog, we will dive into two of the most important things there are when it comes " +
                "to driver development: How to debug correctly, how to cr..."
        },
        {
            href: "/posts/lord-of-the-ring0-p2",
            headerContent: "Lord Of The Ring0 - Part 2 | A tale of routines, IOCTLs and IRPs",
            subHeaderContent: "Ido Veltzman | 04.08.2022",
            imagePath: "/post-images/lotr02.png",
            imageAlt: "lotr02",
            imageWidth: 135,
            imageHeight: 51,
            postContent: "In the last blog post, we had an introduction to kernel development and what are the " +
                "difficulties when trying to load a driver and how to bypass it. In this blog, I will write more " +
                "about callbacks, how to start writing a rootkit and the difficulties I encountered during my " +
                "development of Nidhogg. As I promised to bring both defensive ..."
        },
        {
            href: "/posts/lord-of-the-ring0-p1",
            headerContent: "Lord Of The Ring0 - Part 1 | Introduction",
            subHeaderContent: "Ido Veltzman | 14.07.2022",
            imagePath: "/post-images/lotr0.png",
            imageAlt: "lotr01",
            imageWidth: 135,
            imageHeight: 51,
            postContent: "This blog post series isn’t a thing I normally do, this will be more like a journey that " +
                "I document during the development of my project Nidhogg. In this series of blogs (which I don’t " +
                "know how long will it be), I’ll write about difficulties I encountered while developing Nidhogg " +
                "and tips & tricks for everyone who wants to star..."
        },
        {
            href: "/posts/rust101-rustomware",
            headerContent: "Rust 101 - Let's Write Rustomware",
            subHeaderContent: "Ido Veltzman | 07.05.2022",
            imagePath: "/post-images/rustsomware.png",
            imageAlt: "rustsomware",
            imageWidth: 135,
            imageHeight: 51,
            postContent: "When I first heard about Rust, my first reaction was “Why?”. The language looked to me as " +
                "a “wannabe” to C and I didn’t understand why it is so popular. I started to read more and more " +
                "about this language and began to like it. To challenge myself, I decided to write rustomware in " +
                "Rust. Later on, I ran into trickster0’s amazing repo..."
        },
        {
            href: "/posts/function-stomping",
            headerContent: "The Good, The Bad and The Stomped Function",
            subHeaderContent: "Ido Veltzman | 28.01.2022",
            imagePath: "/post-images/function-stomping.png",
            imageAlt: "function-stomping",
            imageWidth: 135,
            imageHeight: 51,
            postContent: "When I first heard about ModuleStomping I was charmed since it wasn’t like any other known " +
                "injection method. Every other injection method has something in common: They use VirtualAllocEx to " +
                "allocate a new space within the process, and ModulesStomping does something entirely different: " +
                "Instead of allocating new space in the process..."
        },
        {
            href: "/posts/list-udp-connections",
            headerContent: "UdpInspector - Getting active UDP connections without sniffing",
            subHeaderContent: "Ido Veltzman | 19.08.2021",
            imagePath: "/post-images/udpinspect.png",
            imageAlt: "udpinspect",
            imageWidth: 135,
            imageHeight: 51,
            postContent: "Many times I’ve wondered how comes that there are no tools to get active UDP connections. " +
                "Of course, you can always sniff with Wireshark or any other tool of your choosing but, why Netstat " +
                "doesn’t have it built in? That is the point that I went on a quest to investigate the matter. ..."
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
        <div className="bg-bgInsideDiv p-4 rounded-xl h-full">
            {currentPosts.map(post => (
                <BlogPost key={post.href} {...post} />
            ))}
            <div className="pagination flex flex-row items-center justify-center text-txtSubHeader text-2xl">
                {Array.from({length: totalPages}, (_, i) => i + 1).map(pageNumber => (
                    <div key={pageNumber}>
                        <button className="mx-2" key={pageNumber} onClick={() => handlePageClick(pageNumber)}>
                            {pageNumber}
                        </button>
                    </div>
                ))}
            </div>
        </div>
    );
}