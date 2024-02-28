"use client";

import React, {useState} from 'react';
import Script from 'next/script';
import Image from 'next/image';
import "./globals.css";
import {StyledBarLink} from "@/components/StyledLink";

export default function Layout({children,}: Readonly<{ children: React.ReactNode; }>) {
    const [isOpen, setIsOpen] = useState(false);

    return (
        <html>
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
        <body className="bg-bgRegular min-h-screen">
        <div className="flex flex-col font-lato bg-bgRegular text-txtRegular text-md min-h-screen">
            <div className="flex flex-row w-full bg-bgBar p-1 text-txtSubHeader items-center">
                <div className={`mt-2 w-full flex flex-row pl-8 ${isOpen ? 'hidden' : 'block'}`}>
                    <Image src="/logo.svg" alt="Logo" width={40} height={40} className="mr-4 rounded-xl"/>
                    <div className="mt-2 w-full flex flex-row">
                        <StyledBarLink href="/" content="Ido Veltzman :: Security Research"/>
                    </div>
                </div>
                <div className={`${isOpen ? "flex flex-col items-center justify-center h-64" : ""}`}>
                    <button onClick={() => setIsOpen(!isOpen)} className="md:hidden">
                        <Image src="/kosherburger.svg" alt="Menu" width={50} height={50}/>
                    </button>
                    <div className={`${isOpen ? 'flex flex-col w-screen h-screen z-10' : 'hidden'}
                                md:flex md:flex-row items-center justify-center`}>
                        <div className={`mt-2 w-full flex flex-row ${isOpen ? "justify-center" : "justify-end pr-8"}`}>
                            <StyledBarLink href="/posts" content="Posts" isBurger={isOpen}/>
                        </div>
                        <div className={`mt-2 w-full flex flex-row ${isOpen ? "justify-center" : "justify-end pr-8"}`}>
                            <StyledBarLink href="/about" content="About" isBurger={isOpen}/>
                        </div>
                    </div>
                </div>
            </div>
            <div className="p-5 lg:p-8">
                {children}
            </div>
        </div>
        <div className="flex flex-row bg-bgBar text-txtSubHeader items-center">
            <div className="mt-2 w-full flex flex-row pl-2 lg:pl-8">
                <Image src="/logo.svg" alt="Logo" width={50} height={50} className="mr-4 rounded-xl"/>
                <p className="mt-2">© {new Date().getFullYear()} Ido Veltzman - All Rights Reserved</p>
            </div>
            <div className="flex flex-col items-center">
                <div className="mt-2 flex flex-row justify-center pl-5 pt-2 lg:pr-8 lg:pl-0 lg:pt-1">
                    <div className="lg:flex lg:flex-row">
                        <a href="https://x.com/idov31" className="mb-2 mr-6 pt-1">
                            <div className="responsive-image-container">
                                <Image src="/x.svg" alt="X" width={25} height={25} className="responsive-image"/>
                            </div>
                        </a>
                        <a href="https://t.me/idov31" className="mb-2 mr-6">
                            <div className="responsive-image-container">
                                <Image src="/telegram.svg" alt="Telegram" width={35} height={35}
                                       className="responsive-image"/>
                            </div>
                        </a>
                    </div>
                    <div className="lg:flex lg:flex-row">
                        <a href="https://github.com/idov31" className="mb-2 mr-6">
                            <div className="responsive-image-container">
                                <Image src="/github.svg" alt="Github" width={35} height={35}
                                       className="responsive-image"/>
                            </div>
                        </a>
                        <a href="mailto:idov3110@gmail.com" className="mb-2 mr-6">
                            <div className="responsive-image-container">
                                <Image src="/mail.svg" alt="Mail" width={40} height={40}
                                       className="responsive-image"/>
                            </div>
                        </a>
                    </div>
                </div>
            </div>
        </div>
        </body>
        </html>
    );
}