"use client";

import React, {useState} from 'react';
import Script from 'next/script';
import Image from 'next/image';
import Link from 'next/link';
import "./globals.css";

export default function Layout({children,}: Readonly<{ children: React.ReactNode; }>) {
    const [isOpen, setIsOpen] = useState(false);

    const navLinks = [
        {href: "/posts", label: "Posts"},
        {href: "/about", label: "About"},
    ];

    const socialLinks = [
        {href: "https://x.com/idov31", src: "/x.svg", alt: "X (Twitter)", size: 20},
        {href: "https://t.me/idov31", src: "/telegram.svg", alt: "Telegram", size: 24},
        {href: "https://github.com/idov31", src: "/github.svg", alt: "GitHub", size: 24},
        {href: "mailto:idov3110@gmail.com", src: "/mail.svg", alt: "Email", size: 24},
    ];

    return (
        <html lang="en">
        <head>
            <Script src="https://www.googletagmanager.com/gtag/js?id=G-MVJWHHE6LG" strategy="afterInteractive"/>
            <Script id="gtag-config" strategy="afterInteractive">
                {`
                window.dataLayer = window.dataLayer || [];
                function gtag(){dataLayer.push(arguments);}
                gtag('js', new Date());
                gtag('config', 'G-MVJWHHE6LG');
                `}
            </Script>
            <title>Ido Veltzman :: Security Research</title>
            <link rel="icon" href="/favicon.ico" sizes="any"/>
        </head>
        <body className="bg-bgRegular font-lato text-txtRegular min-h-screen flex flex-col">
            {/* ── Navigation ─────────────────────────── */}
            <header className="nav-glass sticky top-0 z-50">
                <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div className="flex items-center justify-between h-16">
                        {/* Logo */}
                        <Link href="/" className="flex items-center gap-3 group" onClick={() => setIsOpen(false)}>
                            <div className="relative">
                                <Image
                                    src="/logo.svg"
                                    alt="Logo"
                                    width={36}
                                    height={36}
                                    className="rounded-lg ring-1 ring-borderSubtle group-hover:ring-accentPurple transition-all duration-300"
                                />
                            </div>
                            <span className="text-txtHeader font-semibold text-lg hidden sm:block tracking-wide">
                                Ido Veltzman
                            </span>
                        </Link>

                        {/* Desktop nav */}
                        <nav className="hidden md:flex items-center gap-1">
                            {navLinks.map(link => (
                                <Link
                                    key={link.href}
                                    href={link.href}
                                    className="px-4 py-2 rounded-lg text-txtMuted hover:text-txtRegular hover:bg-white/5
                                               transition-all duration-200 text-sm font-medium"
                                >
                                    {link.label}
                                </Link>
                            ))}
                        </nav>

                        {/* Mobile burger */}
                        <button
                            onClick={() => setIsOpen(!isOpen)}
                            aria-label="Toggle menu"
                            aria-expanded={isOpen}
                            className="md:hidden p-2 rounded-lg text-txtMuted hover:text-txtRegular hover:bg-white/5 transition-colors"
                        >
                            <span className="sr-only">Menu</span>
                            <div className="w-5 flex flex-col gap-1.5">
                                <span className={`block h-0.5 bg-current transition-all duration-300 ${isOpen ? 'rotate-45 translate-y-2' : ''}`}/>
                                <span className={`block h-0.5 bg-current transition-all duration-300 ${isOpen ? 'opacity-0' : ''}`}/>
                                <span className={`block h-0.5 bg-current transition-all duration-300 ${isOpen ? '-rotate-45 -translate-y-2' : ''}`}/>
                            </div>
                        </button>
                    </div>
                </div>

                {/* Mobile menu */}
                {isOpen && (
                    <div className="md:hidden border-t border-borderSubtle bg-bgBar/95 backdrop-blur-md">
                        <nav className="max-w-6xl mx-auto px-4 py-3 flex flex-col gap-1">
                            {navLinks.map(link => (
                                <Link
                                    key={link.href}
                                    href={link.href}
                                    onClick={() => setIsOpen(false)}
                                    className="px-4 py-3 rounded-lg text-txtMuted hover:text-txtRegular hover:bg-white/5
                                               transition-colors text-base font-medium"
                                >
                                    {link.label}
                                </Link>
                            ))}
                        </nav>
                    </div>
                )}
            </header>

            {/* ── Main content ───────────────────────── */}
            <main className="flex-1 max-w-6xl mx-auto w-full px-4 sm:px-6 lg:px-8 py-8 lg:py-12">
                {children}
            </main>

            {/* ── Footer ─────────────────────────────── */}
            <footer className="border-t border-borderSubtle bg-bgBar mt-auto">
                <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
                    <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
                        <div className="flex items-center gap-3">
                            <Image src="/logo.svg" alt="Logo" width={28} height={28} className="rounded-md opacity-70"/>
                            <p className="text-txtMuted text-sm">
                                © {new Date().getFullYear()} Ido Veltzman · All Rights Reserved
                            </p>
                        </div>
                        <div className="flex items-center gap-4">
                            {socialLinks.map(link => (
                                <a
                                    key={link.href}
                                    href={link.href}
                                    aria-label={link.alt}
                                    className="text-txtMuted hover:text-txtRegular transition-colors duration-200 opacity-70 hover:opacity-100"
                                >
                                    <div className="responsive-image-container">
                                        <Image
                                            src={link.src}
                                            alt={link.alt}
                                            width={link.size}
                                            height={link.size}
                                            className="responsive-image"
                                        />
                                    </div>
                                </a>
                            ))}
                        </div>
                    </div>
                </div>
            </footer>
        </body>
        </html>
    );
}
