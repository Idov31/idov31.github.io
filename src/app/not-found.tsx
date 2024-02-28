"use client";
import { useEffect, useState } from 'react';
import Image from "next/image";

export default function Custom404() {
    const [requestedUrl, setRequestedUrl] = useState('');
    const [msg, setMsg] = useState("404 - Page Not Found :(");

    useEffect(() => {
        setRequestedUrl(window.location.href);
    }, []);

    useEffect(() => {
        if (requestedUrl === 'https://idov31.github.io/2023/07/19/lord-of-the-ring0-p5.html') {
            window.location.href = 'https://idov31.github.io/posts/lord-of-the-ring0-p5';
            setMsg("You will be redirected shortly...");
        }
        else if (requestedUrl === 'https://idov31.github.io/2023/02/24/lord-of-the-ring0-p4.html') {
            window.location.href = 'https://idov31.github.io/posts/lord-of-the-ring0-p4';
            setMsg("You will be redirected shortly...");
        }
        else if (requestedUrl === 'https://idov31.github.io/2022/11/06/cronos-sleep-obfuscation.html') {
            window.location.href = 'https://idov31.github.io/posts/cronos-sleep-obfuscation';
            setMsg("You will be redirected shortly...");
        }
        else if (requestedUrl === 'https://idov31.github.io/2022/10/30/lord-of-the-ring0-p3.html') {
            window.location.href = 'https://idov31.github.io/posts/lord-of-the-ring0-p3';
            setMsg("You will be redirected shortly...");
        }
        else if (requestedUrl === 'https://idov31.github.io/2022/08/04/lord-of-the-ring0-p2.html') {
            window.location.href = 'https://idov31.github.io/posts/lord-of-the-ring0-p2';
            setMsg("You will be redirected shortly...");
        }
        else if (requestedUrl === 'https://idov31.github.io/2022/07/14/lord-of-the-ring0-p1.html') {
            window.location.href = 'https://idov31.github.io/posts/lord-of-the-ring0-p1';
            setMsg("You will be redirected shortly...");
        }
        else if (requestedUrl === 'https://idov31.github.io/2022/05/07/rust101-rustomware.html') {
            window.location.href = 'https://idov31.github.io/posts/rust101-rustomware';
            setMsg("You will be redirected shortly...");
        }
        else if (requestedUrl === 'https://idov31.github.io/2022/01/28/function-stomping.html') {
            window.location.href = 'https://idov31.github.io/posts/function-stomping';
            setMsg("You will be redirected shortly...");
        }
        else if (requestedUrl === 'https://idov31.github.io/2021/08/19/list-udp-connections.html') {
            window.location.href = 'https://idov31.github.io/posts/list-udp-connections';
            setMsg("You will be redirected shortly...");
        }
        else if (requestedUrl === 'https://idov31.github.io/rickroll') {
            window.location.href = 'https://www.youtube.com/watch?v=dQw4w9WgXcQ';
            setMsg("Never gonna give you up...");
        }
    }, [requestedUrl]);

    return (
        <div className="flex flex-col items-center text-center justify-center">
            <h1 className="text-txtHeader text-3xl text-center">{msg}</h1>
            {msg === "404 - Page Not Found :(" && <div className="pt-12">
                <Image src="/sadpepe.png" alt="sadpepe" width="200" height="200" />
            </div>}
        </div>
    );
}