"use client";

import React, {useState, useEffect} from 'react';
import Script from 'next/script';
import Image from 'next/image';
import Link from 'next/link';
import {usePathname} from 'next/navigation';
import "./globals.css";

const navLinks = [
    {href: "/", label: "Home"},
    {href: "/posts", label: "Posts"},
    {href: "/about", label: "About"},
];

const socialLinks = [
    {href: "https://x.com/idov31", icon: "/x.svg", alt: "X (Twitter)", size: 22},
    {href: "https://t.me/idov31", icon: "/telegram.svg", alt: "Telegram", size: 28},
    {href: "https://github.com/idov31", icon: "/github.svg", alt: "GitHub", size: 28},
    {href: "mailto:idov3110@gmail.com", icon: "/mail.svg", alt: "Email", size: 30},
];

export default function Layout({children}: Readonly<{ children: React.ReactNode }>) {
    const [menuOpen, setMenuOpen] = useState(false);
    const [scrolled, setScrolled] = useState(false);
    const pathname = usePathname();

    useEffect(() => {
        const handleScroll = () => setScrolled(window.scrollY > 20);
        window.addEventListener('scroll', handleScroll);
        return () => window.removeEventListener('scroll', handleScroll);
    }, []);

    useEffect(() => {
        setMenuOpen(false);
    }, [pathname]);

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
            <meta name="viewport" content="width=device-width, initial-scale=1"/>
            <link rel="icon" href="/favicon.ico" sizes="any"/>
        </head>
        <body className="bg-bgRegular min-h-screen font-lato text-txtRegular">

        {/* ── Navbar ──────────────────────────────────────────── */}
        <header
            className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
                scrolled
                    ? 'bg-bgBar/95 backdrop-blur-sm shadow-lg shadow-black/30 border-b border-borderPurple'
                    : 'bg-bgBar border-b border-borderPurple'
            }`}
        >
            <nav className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
                <div className="flex items-center justify-between h-16">

                    {/* Logo */}
                    <Link href="/" className="flex items-center gap-3 group">
                        <Image
                            src="/logo.svg"
                            alt="Ido Veltzman"
                            width={36}
                            height={36}
                            className="rounded-lg transition-transform duration-200 group-hover:scale-105"
                        />
                        <div className="hidden sm:block">
                            <span className="text-txtHeader font-cinzel font-semibold text-lg leading-none">
                                Ido Veltzman
                            </span>
                            <p className="section-label mt-0.5">Security Research</p>
                        </div>
                    </Link>

                    {/* Desktop nav */}
                    <div className="hidden md:flex items-center gap-1">
                        {navLinks.map(({href, label}) => {
                            const isActive = href === '/' ? pathname === '/' : pathname.startsWith(href);
                            return (
                                <Link
                                    key={href}
                                    href={href}
                                    className={`px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200 ${
                                        isActive
                                            ? 'text-txtHeader bg-borderPurple'
                                            : 'text-txtSubHeader hover:text-txtHeader hover:bg-white/5'
                                    }`}
                                >
                                    {label}
                                </Link>
                            );
                        })}
                    </div>

                    {/* Mobile menu toggle */}
                    <button
                        onClick={() => setMenuOpen(!menuOpen)}
                        className="md:hidden flex flex-col justify-center items-center w-10 h-10 gap-1.5"
                        aria-label="Toggle menu"
                    >
                        <span className={`block h-0.5 bg-txtSubHeader transition-all duration-300 ${menuOpen ? 'w-6 rotate-45 translate-y-2' : 'w-6'}`}/>
                        <span className={`block h-0.5 bg-txtSubHeader transition-all duration-300 ${menuOpen ? 'opacity-0 w-0' : 'w-5'}`}/>
                        <span className={`block h-0.5 bg-txtSubHeader transition-all duration-300 ${menuOpen ? 'w-6 -rotate-45 -translate-y-2' : 'w-4'}`}/>
                    </button>
                </div>

                {/* Mobile menu */}
                {menuOpen && (
                    <div className="md:hidden pb-4 border-t border-borderPurple mt-2 pt-4 animate-fade-in">
                        {navLinks.map(({href, label}) => {
                            const isActive = href === '/' ? pathname === '/' : pathname.startsWith(href);
                            return (
                                <Link
                                    key={href}
                                    href={href}
                                    className={`block px-4 py-3 rounded-lg text-base mb-1 transition-all ${
                                        isActive
                                            ? 'text-txtHeader bg-borderPurple'
                                            : 'text-txtSubHeader hover:text-txtHeader hover:bg-white/5'
                                    }`}
                                >
                                    {label}
                                </Link>
                            );
                        })}
                    </div>
                )}
            </nav>
        </header>

        {/* ── Main content ────────────────────────────────────── */}
        <main className="pt-16 min-h-screen">
            <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-8 lg:py-12">
                {children}
            </div>
        </main>

        {/* ── Footer ──────────────────────────────────────────── */}
        <footer className="border-t border-borderPurple bg-bgBar mt-12">
            <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
                <div className="flex flex-col sm:flex-row items-center justify-between gap-6">

                    {/* Brand */}
                    <div className="flex items-center gap-3">
                        <Image src="/logo.svg" alt="Logo" width={40} height={40} className="rounded-lg"/>
                        <div>
                            <p className="text-txtSubHeader font-cinzel font-semibold">Ido Veltzman</p>
                            <p className="text-txtMuted text-sm">
                                © {new Date().getFullYear()} · All Rights Reserved
                            </p>
                        </div>
                    </div>

                    {/* Social links */}
                    <div className="flex items-center gap-5">
                        {socialLinks.map(({href, icon, alt, size}) => (
                            <a
                                key={href}
                                href={href}
                                target={href.startsWith('mailto') ? undefined : '_blank'}
                                rel="noopener noreferrer"
                                className="opacity-70 hover:opacity-100 transition-opacity duration-200"
                                aria-label={alt}
                            >
                                <div className="responsive-image-container">
                                    <Image
                                        src={icon}
                                        alt={alt}
                                        width={size}
                                        height={size}
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
