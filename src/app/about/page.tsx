"use client";

import StyledLink from "@/components/StyledLink";
import React, { useEffect } from "react";

const skills = [
    "Reverse Engineering",
    "OS Internals",
    "Security Research",
    "Vulnerability Research",
    "Malware Development",
    "Exploit Development",
    "Kernel Development",
];

export default function About() {
    useEffect(() => { document.title = "Ido Veltzman :: About"; }, []);
    return (
        <div className="animate-fade-in max-w-3xl">
            {/* ── Page header ────────────────────────── */}
            <div className="mb-10">
                <div className="badge badge-purple mb-3">About</div>
                <h1 className="text-4xl font-bold text-txtHeader mb-4">Ido Veltzman</h1>
                <p className="text-txtMuted text-lg leading-relaxed">
                    Ido Veltzman is a senior security researcher specialising in reverse engineering, operating system internals, vulnerability research, and exploit development. His work spans UEFI, hypervisors, kernel, and user mode, where he has developed advanced evasion, persistence, and injection techniques. Ido is known for translating deep technical research into practical offensive tradecraft, and regularly publishes papers and presents to the global cybersecurity community.
                </p><br />
                <p className="text-txtMuted text-lg leading-relaxed">
                    You can view my public work under my{" "}
                    <StyledLink href="https://github.com/idov31" content="GitHub account" textSize="text-sm" />.
                </p>
            </div>

            {/* ── Skills ─────────────────────────────── */}
            <section className="mb-10 card-surface rounded-xl p-6">
                <h2 className="text-xl font-semibold text-txtSubHeader mb-4">Expertise</h2>
                <div className="flex flex-wrap gap-2">
                    {skills.map(skill => (
                        <span key={skill} className="badge badge-purple">{skill}</span>
                    ))}
                </div>
            </section>

            {/* ── Projects ───────────────────────────── */}
            <section className="mb-10">
                <h2 className="text-xl font-semibold text-txtSubHeader mb-4">Notable Projects</h2>
                <ul className="space-y-3">
                    {[
                        { href: "https://github.com/Idov31/Nidhogg", name: "Nidhogg", desc: "Windows rootkit for Intel x64 with 25+ features, demonstrating rootkit techniques compatible with all Windows 10 and Windows 11 versions." },
                        { href: "https://github.com/Idov31/NovaHypervisor", name: "NovaHypervisor", desc: "Windows hypervisor for Intel x64: defensive host hypervisor for Windows designed to mitigate kernel-level attacks including BYOVD, compatible with VMware and Hyper-V." },
                        { href: "https://github.com/Idov31/Jormungandr", name: "Jormungandr", desc: "A kernel implementation of a COFF loader, allowing kernel developers to load and execute their COFFs in the kernel." },
                        { href: "https://github.com/Idov31/Cronos", name: "Cronos", desc: "A PoC for a sleep obfuscation technique leveraging waitable timers to evade memory scanners (PE-Sieve, Moneta, etc.)" },
                        { href: "https://github.com/Idov31/Venom", name: "Venom", desc: "A library performing evasive communication using a stolen browser socket." },
                        { href: "https://github.com/Idov31/Sandman", name: "Sandman", desc: "An NTP-based backdoor for operations in hardened networks." },
                    ].map(item => (
                        <li key={item.name} className="card-surface rounded-xl p-4 flex gap-3 group">
                            <span className="text-accentPurple mt-0.5 flex-shrink-0">▸</span>
                            <div>
                                <StyledLink href={item.href} content={item.name} textSize="text-sm font-semibold" />
                                <p className="text-txtMuted text-sm mt-0.5">{item.desc}</p>
                            </div>
                        </li>
                    ))}
                </ul>
            </section>

            {/* ── Publications ───────────────────────── */}
            <section className="mb-10">
                <h2 className="text-xl font-semibold text-txtSubHeader mb-4">Notable Publications</h2>
                <ul className="space-y-3">
                    <li className="card-surface rounded-xl p-4 flex gap-3">
                        <span className="text-accentPurple mt-0.5 flex-shrink-0">▸</span>
                        <div>
                            <StyledLink
                                href="https://idov31.github.io/posts/lord-of-the-ring0-p1"
                                content="Lord Of The Ring0 Series"
                                textSize="text-sm font-semibold"
                            />
                            <p className="text-txtMuted text-sm mt-0.5">
                                An introductory series to Windows kernel development covering callbacks, IRP hooks,
                                kernel-to-user communication, and more.
                            </p>
                        </div>
                    </li>
                    <li className="card-surface rounded-xl p-4 flex gap-3">
                        <span className="text-accentPurple mt-0.5 flex-shrink-0">▸</span>
                        <div>
                            <StyledLink
                                href="https://www.youtube.com/watch?v=edI6tpBO-pY"
                                content="Kernel Games: The Ballad of Offense & Defense [X33fCon 2024]"
                                textSize="text-sm font-semibold"
                            />
                            <p className="text-txtMuted text-sm mt-0.5">
                                A talk in Poland about creating stealthy rootkits to help red teams remain persistent,
                                evade EDRs, and integrate with existing C2 environments.
                            </p>
                        </div>
                    </li>
                    <li className="card-surface rounded-xl p-4 flex gap-3">
                        <span className="text-accentPurple mt-0.5 flex-shrink-0">▸</span>
                        <div>
                            <StyledLink
                                href="https://www.youtube.com/watch?v=CVJmGfElqw0"
                                content="(Lady|)Lord Of The Ring [BSidesTLV 2023]"
                                textSize="text-sm font-semibold"
                            />
                            <p className="text-txtMuted text-sm mt-0.5">
                                A talk at BSidesTLV covering the functionality of Nidhogg alongside an explanation of
                                the Windows kernel world.
                            </p>
                        </div>
                    </li>
                    <li className="card-surface rounded-xl p-4 flex gap-3">
                        <span className="text-accentPurple mt-0.5 flex-shrink-0">▸</span>
                        <div>
                            <StyledLink
                                href="https://www.digitalwhisper.co.il/"
                                content="DigitalWhisper Publications"
                                textSize="text-sm font-semibold"
                            />
                            <p className="text-txtMuted text-sm mt-0.5">
                                Articles in one of Israel&#39;s oldest active security zines, covering a{" "}
                                <StyledLink href="https://www.digitalwhisper.co.il/files/Zines/0x78/DW120-6-HotKeyExploitation.pdf" content="persistence method" textSize="text-sm" />,{" "}
                                an <StyledLink href="https://www.digitalwhisper.co.il/files/Zines/0x89/DW137-2-StompedFunctions.pdf" content="injection method" textSize="text-sm" />,
                                and <StyledLink href="https://www.digitalwhisper.co.il/files/Zines/0x94/DW148-2-VenomPoisoningSockets.pdf" content="evasive communication" textSize="text-sm" />.
                            </p>
                        </div>
                    </li>
                </ul>
            </section>

            {/* ── Contact ─────────────────────────────── */}
            <section className="card-surface rounded-xl p-6">
                <h2 className="text-xl font-semibold text-txtSubHeader mb-3">Get In Touch</h2>
                <p className="text-txtMuted text-sm leading-relaxed">
                    Feel free to reach out via{" "}
                    <StyledLink href="https://x.com/idov31" content="X (Twitter)" textSize="text-sm" />,{" "}
                    <StyledLink href="https://t.me/idov31" content="Telegram" textSize="text-sm" />, or{" "}
                    <StyledLink href="mailto:idov3110@gmail.com" content="email" textSize="text-sm" />{" "}
                    regarding any of my projects or publications. Enjoy the blog!
                </p>
            </section>
        </div>
    );
}

