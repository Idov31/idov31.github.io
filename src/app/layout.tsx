"use client";

import React, {useEffect, useState} from 'react';
import Script from 'next/script';
import Image from 'next/image';
import Link from 'next/link';
import HeaderSearch from '@/components/HeaderSearch';
import "./globals.css";

function SunIcon() {
    return (
        <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor"
             strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <circle cx="12" cy="12" r="5"/>
            <line x1="12" y1="1" x2="12" y2="3"/>
            <line x1="12" y1="21" x2="12" y2="23"/>
            <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/>
            <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/>
            <line x1="1" y1="12" x2="3" y2="12"/>
            <line x1="21" y1="12" x2="23" y2="12"/>
            <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/>
            <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>
        </svg>
    );
}

function MoonIcon() {
    return (
        <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor"
             strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>
        </svg>
    );
}

function SearchIcon() {
    return (
        <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor"
             strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <circle cx="11" cy="11" r="8"/>
            <path d="m21 21-4.35-4.35"/>
        </svg>
    );
}

export default function Layout({children}: Readonly<{ children: React.ReactNode }>) {
    const [isMenuOpen, setIsMenuOpen] = useState(false);
    const [isDark, setIsDark] = useState(true);
    const [isSearchOpen, setIsSearchOpen] = useState(false);

    // Sync state with the class applied by the anti-FOUC script
    useEffect(() => {
        const saved = localStorage.getItem('theme');
        setIsDark(saved !== 'light');
    }, []);

    const toggleTheme = () => {
        const next = !isDark;
        setIsDark(next);
        if (next) {
            document.documentElement.classList.add('dark');
            localStorage.setItem('theme', 'dark');
        } else {
            document.documentElement.classList.remove('dark');
            localStorage.setItem('theme', 'light');
        }
    };

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
        <html lang="en" className="dark" suppressHydrationWarning>
        <head>
            {/* Anti-FOUC: apply theme class before first paint */}
            <script dangerouslySetInnerHTML={{__html: `
                (function(){
                    var t=localStorage.getItem('theme');
                    if(t==='light'){document.documentElement.classList.remove('dark');}
                    else{document.documentElement.classList.add('dark');}
                })();
            `}}/>
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
                        <Link href="/" className="flex items-center gap-3 group" onClick={() => {
                            setIsMenuOpen(false);
                            setIsSearchOpen(false);
                        }}>
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

                        <div className="flex items-center gap-2">
                            <div className="hidden md:block">
                                <button
                                    type="button"
                                    onClick={() => setIsSearchOpen((current) => !current)}
                                    className="theme-toggle"
                                    aria-label="Search posts"
                                    aria-expanded={isSearchOpen}
                                    title="Search posts"
                                >
                                    <SearchIcon/>
                                </button>
                            </div>

                            {/* Desktop nav links */}
                            <nav className="hidden md:flex items-center gap-1">
                                {navLinks.map(link => (
                                    <Link
                                        key={link.href}
                                        href={link.href}
                                        onClick={() => setIsSearchOpen(false)}
                                        className="px-4 py-2 rounded-lg text-txtMuted hover:text-txtRegular hover:bg-[var(--nav-hover-bg)]
                                                   transition-all duration-200 text-sm font-medium"
                                    >
                                        {link.label}
                                    </Link>
                                ))}
                            </nav>

                            {/* Theme toggle — always visible */}
                            <button
                                onClick={toggleTheme}
                                className="theme-toggle"
                                aria-label={isDark ? "Switch to light mode" : "Switch to dark mode"}
                                title={isDark ? "Switch to light mode" : "Switch to dark mode"}
                            >
                                {isDark ? <SunIcon/> : <MoonIcon/>}
                            </button>

                            {/* Mobile burger */}
                            <button
                                onClick={() => setIsMenuOpen(!isMenuOpen)}
                                aria-label="Toggle menu"
                                aria-expanded={isMenuOpen}
                                className="md:hidden p-2 rounded-lg text-txtMuted hover:text-txtRegular hover:bg-[var(--nav-hover-bg)] transition-colors"
                            >
                                <span className="sr-only">Menu</span>
                                <div className="w-5 flex flex-col gap-1.5">
                                    <span className={`block h-0.5 bg-current transition-all duration-300 ${isMenuOpen ? 'rotate-45 translate-y-2' : ''}`}/>
                                    <span className={`block h-0.5 bg-current transition-all duration-300 ${isMenuOpen ? 'opacity-0' : ''}`}/>
                                    <span className={`block h-0.5 bg-current transition-all duration-300 ${isMenuOpen ? '-rotate-45 -translate-y-2' : ''}`}/>
                                </div>
                            </button>
                        </div>
                    </div>
                </div>

                {isSearchOpen && (
                    <div className="hidden md:block border-t border-borderSubtle">
                        <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-3">
                            <div className="ml-auto w-full max-w-md">
                                <HeaderSearch autoFocus onResultClick={() => setIsSearchOpen(false)}/>
                            </div>
                        </div>
                    </div>
                )}

                {/* Mobile menu */}
                {isMenuOpen && (
                    <div className="md:hidden border-t border-borderSubtle bg-bgBar/95 backdrop-blur-md">
                        <div className="max-w-6xl mx-auto px-4 py-3">
                            <div className="pb-3">
                                <HeaderSearch onResultClick={() => setIsMenuOpen(false)}/>
                            </div>
                            <nav className="flex flex-col gap-1">
                                {navLinks.map(link => (
                                    <Link
                                        key={link.href}
                                        href={link.href}
                                        onClick={() => setIsMenuOpen(false)}
                                        className="px-4 py-3 rounded-lg text-txtMuted hover:text-txtRegular hover:bg-[var(--nav-hover-bg)]
                                                   transition-colors text-base font-medium"
                                    >
                                        {link.label}
                                    </Link>
                                ))}
                            </nav>
                        </div>
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

