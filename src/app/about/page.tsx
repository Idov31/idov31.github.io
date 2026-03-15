import Link from "next/link";
import React from "react";

const expertise = [
    "Reverse Engineering",
    "OS Internals",
    "Security Research",
    "Vulnerability Research",
    "Malware Development",
    "Exploit Development",
    "Kernel Development",
];

const projects = [
    {
        name: "Nidhogg",
        href: "https://github.com/Idov31/Nidhogg",
        description: "A multi-functional rootkit to showcase the variety of operations that can be done from kernel space.",
    },
    {
        name: "Jormungandr",
        href: "https://github.com/Idov31/Jormungandr",
        description: "A kernel implementation of a COFF loader, allowing kernel developers to load and execute their COFFs in the kernel.",
    },
    {
        name: "Cronos",
        href: "https://github.com/Idov31/Cronos",
        description: "A PoC for a sleep obfuscation technique leveraging waitable timers to evade memory scanners (PE-Sieve, Moneta, etc.).",
    },
    {
        name: "NovaHypervisor",
        href: "https://github.com/Idov31/NovaHypervisor",
        description: "A defensive x64 Intel host-based hypervisor built to protect against kernel-based attacks.",
    },
    {
        name: "Venom",
        href: "https://github.com/Idov31/Venom",
        description: "A library performing evasive communication using a stolen browser socket.",
    },
    {
        name: "Sandman",
        href: "https://github.com/Idov31/Sandman",
        description: "An NTP-based backdoor designed for operations in hardened networks.",
    },
];

const publications = [
    {
        name: "Lord Of The Ring0 Series",
        href: "https://idov31.github.io/posts/lord-of-the-ring0-p1",
        description: "An introductory series to Windows kernel development covering callbacks, IRP hooks, kernel-to-user communication and more.",
    },
    {
        name: "Kernel Games: The Ballad of Offense & Defense [2024]",
        href: "https://www.youtube.com/watch?v=edI6tpBO-pY",
        description: "Talk at X33fCon (Poland) about stealthy rootkits for red teams — persistence, EDR evasion, and C2 integration.",
    },
    {
        name: "(Lady|)Lord Of The Ring [2023]",
        href: "https://www.youtube.com/watch?v=CVJmGfElqw0",
        description: "BSidesTLV keynote covering Nidhogg's functionality alongside a deep dive into the Windows kernel world.",
    },
    {
        name: "DigitalWhisper Publications",
        href: "https://www.digitalwhisper.co.il/",
        description: "Articles on persistence methods, injection techniques, and evasive socket communication in Israel's oldest active security zine.",
    },
];

export default function About() {
    return (
        <div className="space-y-12 animate-fade-in">

            {/* ── Header ────────────────────────────────────────── */}
            <section>
                <p className="section-label mb-2">About</p>
                <h1 className="text-3xl sm:text-4xl font-cinzel text-txtHeader mb-4">
                    Ido Veltzman
                </h1>
                <div className="terminal-divider"/>
            </section>

            {/* ── Bio + Expertise ───────────────────────────────── */}
            <section className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                <div className="lg:col-span-2 glass-card p-6 sm:p-8 space-y-4">
                    <h2 className="text-xl font-cinzel text-txtSubHeader">Who I Am</h2>
                    <p className="text-txtRegular leading-relaxed">
                        I am an experienced security researcher who has worked in various cybersecurity roles.
                        My work sits at the intersection of offensive and defensive security — building tools
                        that challenge defenders while helping the community learn.
                    </p>
                    <p className="text-txtRegular leading-relaxed">
                        In my free time I work on open-source projects in the areas of evasion, persistence, and
                        injection methods for UEFI, kernel, and user mode. I publish educational papers and
                        present talks to give back to the cybersecurity community.
                    </p>
                    <p className="text-txtSubHeader leading-relaxed">
                        You can view my public work on my{" "}
                        <a
                            href="https://github.com/idov31"
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-txtLink hover:underline"
                        >
                            GitHub account
                        </a>
                        .
                    </p>
                </div>

                <div className="glass-card p-6 sm:p-8">
                    <h2 className="text-xl font-cinzel text-txtSubHeader mb-4">Expertise</h2>
                    <ul className="space-y-2">
                        {expertise.map(skill => (
                            <li key={skill} className="flex items-center gap-3 text-txtRegular text-sm">
                                <span className="w-1.5 h-1.5 rounded-full bg-txtLink flex-shrink-0"/>
                                {skill}
                            </li>
                        ))}
                    </ul>
                </div>
            </section>

            {/* ── Projects ──────────────────────────────────────── */}
            <section>
                <h2 className="text-2xl font-cinzel text-txtSubHeader mb-6">Notable Projects</h2>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
                    {projects.map(project => (
                        <a
                            key={project.name}
                            href={project.href}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="glass-card p-5 card-hover group flex flex-col gap-2"
                        >
                            <h3 className="text-txtHeader font-semibold group-hover:text-txtSubHeader
                                           transition-colors duration-200">
                                {project.name}
                            </h3>
                            <p className="text-txtMuted text-sm leading-relaxed flex-1">
                                {project.description}
                            </p>
                            <span className="text-txtLink text-xs mt-2 group-hover:underline">
                                View on GitHub →
                            </span>
                        </a>
                    ))}
                </div>
            </section>

            {/* ── Publications ──────────────────────────────────── */}
            <section>
                <h2 className="text-2xl font-cinzel text-txtSubHeader mb-6">Notable Publications</h2>
                <div className="space-y-4">
                    {publications.map(pub => (
                        <a
                            key={pub.name}
                            href={pub.href}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="glass-card p-5 card-hover group flex flex-col sm:flex-row gap-3"
                        >
                            <div className="flex-1">
                                <h3 className="text-txtHeader font-semibold group-hover:text-txtSubHeader
                                               transition-colors duration-200 mb-1">
                                    {pub.name}
                                </h3>
                                <p className="text-txtMuted text-sm leading-relaxed">{pub.description}</p>
                            </div>
                            <span className="text-txtLink text-sm flex-shrink-0 group-hover:underline self-start sm:self-center">
                                View →
                            </span>
                        </a>
                    ))}
                </div>
            </section>

            {/* ── Contact ───────────────────────────────────────── */}
            <section className="glass-card p-6 sm:p-8">
                <h2 className="text-xl font-cinzel text-txtSubHeader mb-3">Get in Touch</h2>
                <p className="text-txtRegular leading-relaxed">
                    Feel free to reach out via{" "}
                    <a href="https://x.com/idov31" target="_blank" rel="noopener noreferrer"
                       className="text-txtLink hover:underline">X (Twitter)</a>
                    ,{" "}
                    <a href="https://t.me/idov31" target="_blank" rel="noopener noreferrer"
                       className="text-txtLink hover:underline">Telegram</a>
                    {" "}or{" "}
                    <a href="mailto:idov3110@gmail.com"
                       className="text-txtLink hover:underline">email</a>
                    {" "}regarding any of my projects or publications.
                    Enjoy reading the blog and have fun!
                </p>
            </section>
        </div>
    );
}
