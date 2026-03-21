"use client";

import Image from 'next/image';
import Link from 'next/link';
import React, { useEffect } from "react";
import ProjectBox from "@/components/ProjectBox";
import {blogPosts} from "@/data/blogPosts";

export default function Home() {
    const projects = [
        {
            imagePath: "/projects-images/jormungandr.png",
            projectLink: "https://github.com/Idov31/Jormungandr",
            projectName: "Jormungandr",
            description: "A kernel implementation of a COFF loader, allowing kernel developers to load and execute their COFFs in the kernel.",
        },
        {
            imagePath: "/projects-images/nidhogg.png",
            projectLink: "https://github.com/Idov31/Nidhogg",
            projectName: "Nidhogg",
            description: "Windows rootkit for Intel x64 with 25+ features, demonstrating rootkit techniques compatible with all Windows 10 and Windows 11 versions.",
        },
        {
            imagePath: "/projects-images/novahypervisor.png",
            projectLink: "https://github.com/Idov31/NovaHypervisor",
            projectName: "NovaHypervisor",
            description: "Windows hypervisor for Intel x64: defensive host hypervisor for Windows designed to mitigate kernel-level attacks including BYOVD, compatible with VMware and Hyper-V.",
        },
        {
            imagePath: "/projects-images/cronos.png",
            projectLink: "https://github.com/Idov31/Cronos",
            projectName: "Cronos",
            description: "A sleep obfuscation technique leveraging waitable timers to evade memory scanners.",
        },
        {
            imagePath: "/projects-images/sandman.png",
            projectLink: "https://github.com/Idov31/Sandman",
            projectName: "Sandman",
            description: "An NTP-based backdoor for operations in hardened networks.",
        },
        {
            imagePath: "/projects-images/venom.png",
            projectLink: "https://github.com/Idov31/Venom",
            projectName: "Venom",
            description: "A library performing evasive communication using a stolen browser socket.",
        },
    ];

    const latestPost = blogPosts.reduce((latest, post) => {
        if (!latest) {
            return post;
        }

        return new Date(post.subHeaderContent).getTime() > new Date(latest.subHeaderContent).getTime()
            ? post
            : latest;
    }, blogPosts[0]);
    useEffect(() => { document.title = "Ido Veltzman :: Security Research"; }, []);

    return (
        <div className="animate-fade-in">
            {/* ── Latest Post ────────────────────────── */}
            <section className="mb-14">
                <div className="flex items-center gap-3 mb-6">
                    <h2 className="text-xl font-semibold text-txtSubHeader">Latest Post</h2>
                    <div className="flex-1 h-px bg-borderSubtle"/>
                    <Link href="/posts" className="text-txtLink text-sm hover:underline transition-colors">
                        View all →
                    </Link>
                </div>
                <Link href={latestPost.href} className="block group">
                    <div className="card-surface rounded-2xl p-6 lg:p-8 flex flex-col lg:flex-row gap-6">
                        <div className="flex-1">
                            <div className="badge badge-purple mb-3">{latestPost.subHeaderContent}</div>
                            <h3 className="text-2xl lg:text-3xl font-bold text-txtHeader group-hover:text-txtSubHeader
                                           transition-colors duration-200 mb-3 leading-tight">
                                {latestPost.headerContent}
                            </h3>
                            <p className="text-txtMuted text-base leading-relaxed">
                                {latestPost.postContent}
                            </p>
                            <span className="inline-flex items-center gap-1 mt-4 text-txtLink text-sm font-medium
                                             group-hover:gap-2 transition-all duration-200">
                                Read post <span>→</span>
                            </span>
                        </div>
                        <div className="lg:w-72 flex-shrink-0 flex items-center justify-center">
                            <Image
                                src={latestPost.imagePath}
                                alt={latestPost.imageAlt}
                                width={420}
                                height={160}
                                className="rounded-xl object-cover w-full"
                            />
                        </div>
                    </div>
                </Link>
            </section>

            {/* ── Projects ───────────────────────────── */}
            <section className="pt-16">
                <div className="flex items-center gap-3 mb-6">
                    <h2 className="text-xl font-semibold text-txtSubHeader">Open Source Projects</h2>
                    <div className="flex-1 h-px bg-borderSubtle"/>
                    <a
                        href="https://github.com/idov31"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-txtLink text-sm hover:underline transition-colors"
                    >
                        GitHub →
                    </a>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
                    {projects.map(project => (
                        <ProjectBox key={project.projectName} {...project} />
                    ))}
                </div>
            </section>
        </div>
    );
}

