import Image from 'next/image';
import Link from 'next/link';
import React from "react";

const projects = [
    {
        name: "Jormungandr",
        link: "https://github.com/Idov31/Jormungandr",
        image: "/projects-images/jormungandr.png",
        description: "A kernel implementation of a COFF loader, allowing kernel developers to load and execute their COFFs in the kernel.",
        tags: ["Kernel", "C++"],
    },
    {
        name: "Nidhogg",
        link: "https://github.com/Idov31/Nidhogg",
        image: "/projects-images/nidhogg.png",
        description: "A multi-functional rootkit to showcase the variety of operations that can be done from kernel space.",
        tags: ["Rootkit", "Kernel", "C++"],
    },
    {
        name: "NovaHypervisor",
        link: "https://github.com/Idov31/NovaHypervisor",
        image: "/projects-images/novahypervisor.png",
        description: "A defensive x64 Intel host-based hypervisor built to protect against kernel-based attacks.",
        tags: ["Hypervisor", "Defense"],
    },
    {
        name: "Cronos",
        link: "https://github.com/Idov31/Cronos",
        image: "/projects-images/cronos.png",
        description: "A sleep obfuscation technique leveraging waitable timers to evade memory scanners (PE-Sieve, Moneta, etc.).",
        tags: ["Evasion", "C++"],
    },
    {
        name: "Sandman",
        link: "https://github.com/Idov31/Sandman",
        image: "/projects-images/sandman.png",
        description: "An NTP-based backdoor designed for operations in hardened networks.",
        tags: ["C2", "Backdoor"],
    },
    {
        name: "Venom",
        link: "https://github.com/Idov31/Venom",
        image: "/projects-images/venom.png",
        description: "A library performing evasive communication using a stolen browser socket.",
        tags: ["Evasion", "C++"],
    },
];

export default function Home() {
    return (
        <div className="space-y-16 animate-fade-in">

            {/* ── Hero ──────────────────────────────────────────── */}
            <section className="flex flex-col-reverse md:flex-row items-center gap-10 pt-4">
                <div className="flex-1 space-y-5">
                    <p className="section-label">Security Researcher</p>
                    <h1 className="text-4xl sm:text-5xl lg:text-6xl font-cinzel font-bold gradient-text leading-tight">
                        Ido Veltzman
                    </h1>
                    <p className="text-txtSubHeader text-lg leading-relaxed max-w-xl">
                        Kernel developer, offensive security researcher and open-source author.
                        I build rootkits, hypervisors and evasion tooling — and write about all of it.
                    </p>
                    <div className="flex flex-wrap gap-3 pt-2">
                        <Link
                            href="/posts"
                            className="px-5 py-2.5 rounded-lg bg-txtHeader/10 border border-borderPurple
                                       text-txtHeader font-medium hover:bg-txtHeader/20 transition-colors duration-200"
                        >
                            Read the Blog
                        </Link>
                        <Link
                            href="/about"
                            className="px-5 py-2.5 rounded-lg bg-transparent border border-borderAccent
                                       text-txtLink font-medium hover:bg-txtLink/10 transition-colors duration-200"
                        >
                            About Me
                        </Link>
                    </div>
                </div>
                <div className="flex-shrink-0">
                    <div className="w-36 h-36 md:w-48 md:h-48 rounded-2xl overflow-hidden border-2 border-borderPurple
                                    shadow-glow">
                        <Image
                            src="/avatar-icon.png"
                            alt="Ido Veltzman"
                            width={192}
                            height={192}
                            className="w-full h-full object-cover"
                            priority
                        />
                    </div>
                </div>
            </section>

            {/* ── Terminal divider ──────────────────────────────── */}
            <div className="terminal-divider"/>

            {/* ── Featured post ─────────────────────────────────── */}
            <section>
                <p className="section-label mb-4">Latest Post</p>
                <Link href="/posts/lord-of-the-ring0-p6" className="block group">
                    <div className="glass-card p-6 sm:p-8 card-hover">
                        <div className="flex flex-col lg:flex-row gap-6 items-start">
                            <div className="flex-1 space-y-3">
                                <span className="tag-badge">Lord Of The Ring0 · Part 6</span>
                                <h2 className="text-2xl sm:text-3xl text-txtHeader font-cinzel leading-snug
                                               group-hover:text-txtSubHeader transition-colors duration-200">
                                    Lord Of The Ring0 - Part 6 | Conclusion
                                </h2>
                                <p className="text-txtMuted text-sm">Ido Veltzman &nbsp;·&nbsp; 31.03.2024</p>
                                <p className="text-txtSubHeader leading-relaxed text-base">
                                    In this final post, we write a simple driver capable of bypassing AMSI
                                    to demonstrate patching usermode memory from the kernel — tying together
                                    everything learned in the series.
                                </p>
                                <span className="inline-block text-txtLink text-sm mt-2 group-hover:underline">
                                    Read post →
                                </span>
                            </div>
                            <div className="flex-shrink-0 lg:self-center">
                                <Image
                                    src="/post-images/lotr06.png"
                                    alt="Lord Of The Ring0 Part 6"
                                    width={260}
                                    height={98}
                                    className="rounded-xl border border-borderPurple"
                                />
                            </div>
                        </div>
                    </div>
                </Link>
            </section>

            {/* ── Open Source Projects ──────────────────────────── */}
            <section>
                <div className="flex items-center justify-between mb-6">
                    <p className="section-label">Open Source Projects</p>
                    <a
                        href="https://github.com/idov31"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-txtLink text-sm hover:underline"
                    >
                        View on GitHub →
                    </a>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-5">
                    {projects.map((project) => (
                        <a
                            key={project.name}
                            href={project.link}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="glass-card p-5 card-hover flex flex-col gap-4 group"
                        >
                            <div className="flex items-center gap-3">
                                <Image
                                    src={project.image}
                                    alt={project.name}
                                    width={48}
                                    height={48}
                                    className="rounded-lg border border-borderPurple"
                                />
                                <h3 className="text-txtHeader font-semibold text-lg group-hover:text-txtSubHeader
                                               transition-colors duration-200">
                                    {project.name}
                                </h3>
                            </div>
                            <p className="text-txtSubHeader text-sm leading-relaxed flex-1">
                                {project.description}
                            </p>
                            <div className="flex flex-wrap gap-2 mt-auto pt-2">
                                {project.tags.map(tag => (
                                    <span key={tag} className="tag-badge">{tag}</span>
                                ))}
                            </div>
                        </a>
                    ))}
                </div>
            </section>
        </div>
    );
}

