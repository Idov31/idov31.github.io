import StyledLink from "@/components/StyledLink";
import React from "react";

export default function Home() {
    return (
        <div className="flex flex-col h-full w-fit bg-bgInsideDiv rounded-xl p-8">
            <h1 className="text-5xl text-txtHeader font-bold">About Me</h1>
            <article className="mt-4">
                My name is Ido Veltzman, I am an experienced security researcher, who has worked in various
                cyber-security roles close to six years. My main expertise are:

                <ul className="list-disc pl-10 pt-8">
                    <li className="mb-4">Reverse Engineering</li>
                    <li className="mb-4">OS Internals</li>
                    <li className="mb-4">Kernel Development</li>
                    <li className="mb-4">Malware Development</li>
                    <li className="mb-4">Exploit Development</li>
                    <li className="mb-4">Security Research</li>
                </ul>
                <p className="pt-4">In my free time, I am working on projects in the areas of evasion, persistence and
                    injection methods
                    for both kernel mode and user mode and releasing them under <a href="https://github.com/idov31">my
                        GitHub account</a>.</p>
            </article>
            <h2 className="text-4xl text-txtSubHeader font-bold mt-8">Notable Projects & Publications</h2>
            <article>
                <h3 className="text-2xl text-txtSubHeader">Projects</h3>
                <br/>
                <ul className="list-disc pl-10">
                    <li className="mb-4">
                        <StyledLink href="https://github.com/Idov31/Nidhogg" content="Nidhogg"/>
                        : Nidhogg is a multi-functional rootkit to showcase the variety of operations that
                        can be done from kernel space.
                    </li>
                    <li className="mb-4">
                        <StyledLink href="https://github.com/Idov31/Jormungandr" content="Jormungandr"/>
                        : Jormungandr is a kernel implementation of a COFF loader, allowing kernel
                        developers to load and execute their COFFs in the kernel.
                    </li>
                    <li className="mb-4">
                        <StyledLink href="https://github.com/Idov31/Cronos" content="Cronos"/>
                        : Cronos is a PoC for a sleep obfuscation technique leveraging waitable timers to evade memory
                        scanners (PE-Sieve, Moneta, etc.)
                    </li>
                    <li className="mb-4">
                        <StyledLink href="https://github.com/Idov31/Venom" content="Venom"/>
                        : Venom is a library that performing evasive communication using stolen browser socket.
                    </li>
                    <li className="mb-4">
                        <StyledLink href="https://github.com/Idov31/Sandman" content="Sandman"/>
                        : Sandman is a NTP based backdoor for operations in hardened networks.
                    </li>
                </ul>
                <br/>
                <h3 className="text-2xl text-txtSubHeader">Notable Publications</h3>
                <br/>
                <ul className="list-disc pl-10">
                    <li className="mb-4">
                        <StyledLink href="https://github.com/Idov31/Nidhogg" content="Lord Of The Ring0 Series"/>
                        : Lord Of The Ring0 is an introductory series to Windows kernel development
                        that covers the basics of Windows kernel development in a security oriented manner including but
                        not limited to callbacks, IRP hooks, communication with user mode from kernel mode and more.
                    </li>
                    <li className="mb-4">
                        <StyledLink href="https://www.youtube.com/watch?v=CVJmGfElqw0"
                                    content="(Lady|)Lord Of The Ring [2023]"/>
                        : A talk in the largest public security conference in
                        Israel, BSidesTLV, that covers some of the functionality that Nidhogg has to offer alongside
                        explanation about the Windows kernel world.
                    </li>
                    <li className="mb-4">
                        <StyledLink href="https://www.digitalwhisper.co.il/"
                                    content="DigitalWhisper Publications"/>
                        : DigitalWhisper is one of the oldest active security zines in Israel that contains various of
                        articles about security, software development and more. I have published several articles in the
                        zine about my own
                        <StyledLink
                            href="https://www.digitalwhisper.co.il/files/Zines/0x78/DW120-6-HotKeyExploitation.pdf"
                            content=" persistence method"/>,
                        <StyledLink
                            href="https://www.digitalwhisper.co.il/files/Zines/0x89/DW137-2-StompedFunctions.pdf"
                            content=" injection method "/>
                        and
                        <StyledLink
                            href="https://www.digitalwhisper.co.il/files/Zines/0x94/DW148-2-VenomPoisoningSockets.pdf"
                            content=" communication in evasive way"/>.
                    </li>
                </ul>
            </article>
            <p className="pt-4">
                Feel free to contact me via <StyledLink href="https://x.com/idov31" content="X (Twitter)"
                                                        textSize="text-md"/>,
                <StyledLink href="https://t.me/idov31" content=" Telegram" textSize="text-md"/> or
                <StyledLink href="mailto:idov3110@gmail.com" content=" mail"
                            textSize="text-md"/> regarding
                any of my projects or publications. Enjoy reading the blog and have fun!
            </p>
        </div>
    );
}
