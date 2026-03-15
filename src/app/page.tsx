import Image from 'next/image';
import Link from 'next/link';
import React from "react";
import ProjectBox from "@/components/ProjectBox";

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
            description: "A multi-functional rootkit showcasing the variety of operations that can be done from kernel space.",
        },
        {
            imagePath: "/projects-images/novahypervisor.png",
            projectLink: "https://github.com/Idov31/NovaHypervisor",
            projectName: "NovaHypervisor",
            description: "A defensive x64 Intel host-based hypervisor to protect against kernel-based attacks.",
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

    return (
        <div className="animate-fade-in">
            {/* ── Hero Section ───────────────────────── */}
            <section className="flex flex-col md:flex-row items-center md:items-start gap-8 pb-12 mb-12 border-b border-borderSubtle">
                <div className="flex-shrink-0">
                    <div className="relative">
                        <div className="absolute inset-0 rounded-full bg-accentPurple/20 blur-xl scale-110"/>
                        <Image
                            src="/avatar-icon.png"
                            alt="Ido Veltzman"
                            width={120}
                            height={120}
                            className="relative rounded-full ring-2 ring-borderMid"
                        />
                    </div>
                </div>
                <div className="flex flex-col items-center md:items-start text-center md:text-left">
                    <div className="badge badge-purple mb-3">Security Researcher</div>
                    <h1 className="text-4xl lg:text-5xl font-bold text-txtHeader mb-3 leading-tight">
                        Ido Veltzman
                    </h1>
                    <p className="text-txtMuted text-lg max-w-xl leading-relaxed mb-6">
                        Security researcher specialising in kernel development, OS internals, and offensive tooling.
                        I build open-source projects and write about what I learn along the way.
                    </p>
                    <div className="flex flex-wrap gap-3 justify-center md:justify-start">
                        <Link
                            href="/posts"
                            className="px-5 py-2.5 bg-accentPurple hover:bg-accentPurple/90 text-white rounded-lg
                                       font-medium text-sm transition-all duration-200 shadow-glow hover:shadow-lg"
                        >
                            Read the Blog
                        </Link>
                        <Link
                            href="/about"
                            className="px-5 py-2.5 border border-borderMid hover:border-accentPurple text-txtMuted
                                       hover:text-txtRegular rounded-lg font-medium text-sm transition-all duration-200"
                        >
                            About Me
                        </Link>
                    </div>
                </div>
            </section>

            {/* ── Latest Post ────────────────────────── */}
            <section className="mb-14">
                <div className="flex items-center gap-3 mb-6">
                    <h2 className="text-xl font-semibold text-txtSubHeader">Latest Post</h2>
                    <div className="flex-1 h-px bg-borderSubtle"/>
                    <Link href="/posts" className="text-txtLink text-sm hover:underline transition-colors">
                        View all →
                    </Link>
                </div>
                <Link href="/posts/lord-of-the-ring0-p6" className="block group">
                    <div className="card-surface rounded-2xl p-6 lg:p-8 flex flex-col lg:flex-row gap-6">
                        <div className="flex-1">
                            <div className="badge badge-purple mb-3">31 Mar 2024</div>
                            <h3 className="text-2xl lg:text-3xl font-bold text-txtHeader group-hover:text-txtSubHeader
                                           transition-colors duration-200 mb-3 leading-tight">
                                Lord Of The Ring0 — Part 6 | Conclusion
                            </h3>
                            <p className="text-txtMuted text-base leading-relaxed">
                                In this post, we write a simple driver capable of bypassing AMSI to demonstrate
                                patching usermode memory from the kernel — wrapping up the Lord Of The Ring0 series.
                            </p>
                            <span className="inline-flex items-center gap-1 mt-4 text-txtLink text-sm font-medium
                                             group-hover:gap-2 transition-all duration-200">
                                Read post <span>→</span>
                            </span>
                        </div>
                        <div className="lg:w-72 flex-shrink-0 flex items-center justify-center">
                            <Image
                                src="/post-images/lotr06.png"
                                alt="Lord of the Ring0 Part 6"
                                width={420}
                                height={160}
                                className="rounded-xl object-cover w-full"
                            />
                        </div>
                    </div>
                </Link>
            </section>

            {/* ── Projects ───────────────────────────── */}
            <section>
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

