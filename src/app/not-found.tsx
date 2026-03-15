"use client";
import { useEffect, useState } from 'react';
import Image from "next/image";
import Link from "next/link";

export default function Custom404() {
    const [requestedUrl, setRequestedUrl] = useState('');
    const [msg, setMsg] = useState("404 — Page Not Found");

    useEffect(() => {
        setRequestedUrl(window.location.href);
    }, []);

    useEffect(() => {
        const redirectMap: Record<string, string> = {
            'https://idov31.github.io/2023/07/19/lord-of-the-ring0-p5.html': '/posts/lord-of-the-ring0-p5',
            'https://idov31.github.io/2023/02/24/lord-of-the-ring0-p4.html': '/posts/lord-of-the-ring0-p4',
            'https://idov31.github.io/2022/11/06/cronos-sleep-obfuscation.html': '/posts/cronos-sleep-obfuscation',
            'https://idov31.github.io/2022/10/30/lord-of-the-ring0-p3.html': '/posts/lord-of-the-ring0-p3',
            'https://idov31.github.io/2022/08/04/lord-of-the-ring0-p2.html': '/posts/lord-of-the-ring0-p2',
            'https://idov31.github.io/2022/07/14/lord-of-the-ring0-p1.html': '/posts/lord-of-the-ring0-p1',
            'https://idov31.github.io/2022/05/07/rust101-rustomware.html': '/posts/rust101-rustomware',
            'https://idov31.github.io/2022/01/28/function-stomping.html': '/posts/function-stomping',
            'https://idov31.github.io/2021/08/19/list-udp-connections.html': '/posts/list-udp-connections',
        };

        if (requestedUrl === 'https://idov31.github.io/rickroll') {
            window.location.href = 'https://www.youtube.com/watch?v=dQw4w9WgXcQ';
            setMsg("Never gonna give you up...");
            return;
        }

        const target = redirectMap[requestedUrl];
        if (target) {
            window.location.href = `https://idov31.github.io${target}`;
            setMsg("Redirecting you shortly...");
        }
    }, [requestedUrl]);

    const isRedirecting = msg !== "404 — Page Not Found";

    return (
        <div className="flex flex-col items-center justify-center text-center py-20 animate-fade-in">
            {isRedirecting ? (
                <p className="text-txtSubHeader text-xl">{msg}</p>
            ) : (
                <>
                    <div className="relative mb-8">
                        <div className="absolute inset-0 rounded-full bg-accentPurple/10 blur-2xl scale-150"/>
                        <Image src="/sadpepe.png" alt="Sad Pepe" width={160} height={160} className="relative"/>
                    </div>
                    <h1 className="text-6xl font-bold text-txtHeader mb-3">404</h1>
                    <p className="text-txtMuted text-lg mb-8">{msg}</p>
                    <Link
                        href="/"
                        className="px-5 py-2.5 bg-accentPurple hover:bg-accentPurple/90 text-white rounded-lg
                                   font-medium text-sm transition-all duration-200"
                    >
                        Back to Home
                    </Link>
                </>
            )}
        </div>
    );
}
