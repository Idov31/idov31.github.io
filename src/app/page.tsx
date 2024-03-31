import Image from 'next/image';
import React from "react";
import ProjectBox from "@/components/ProjectBox";

export default function Home() {
    return (
        <div className="p-5">
            <div className="flex pb-6 border-b-4 border-dotted border-txtLink">
                <div className="flex flex-col">
                    <div className="flex flex-col">
                        <h1 className="text-5xl lg:text-6xl text-txtHeader">Lord Of The Ring0 - Part 6 | Conclusion</h1>
                        <p className="text-txtSubHeader text-xl pt-8 lg:w-4/5">In the last blog post, we learned about
                            two common hooking methods (IRP Hooking and SSDT Hooking) and two different injection
                            techniques from the kernel to the user mode for both shellcode and DLL (APC and
                            CreateThread) with code snippets and examples from Nidhogg. In this blog post , we will
                            write a  simple driver that is capable of bypassing AMSI to demonstrate patching usermode
                            memory from the k...</p>
                    </div>
                    <div className="pt-8">
                        <a href="/posts/lord-of-the-ring0-p6" target="_blank" rel="noopener noreferrer">
                            <button className="bg-bgHomeLine p-4">Click here to read the blog post</button>
                        </a>
                    </div>
                </div>
                <Image src="/post-images/lotr06.png" alt="Latest post image" width={1080} height={405}
                       className="pt-8 hidden lg:block"/>
            </div>
            <div className="p-10 flex flex-col justify-center items-center">
                <div className="flex flex-col justify-center items-center">
                    <div className="lg:flex lg:flex-row">
                        <ProjectBox imagePath="/projects-images/jormungandr.png"
                                    projectLink="https://github.com/Idov31/Jormungandr" projectName="Jormungandr"
                                    description="Jormungandr is a kernel
                                implementation of a COFF loader, allowing kernel developers to load and execute their COFFs
                                in the kernel."/>

                        <ProjectBox imagePath="/projects-images/nidhogg.png"
                                    projectLink="https://github.com/Idov31/Nidhogg" projectName="Nidhogg"
                                    description="Nidhogg is a multi-functional rootkit to showcase the variety of operations
                                    that can be done from kernel space."/>

                        <ProjectBox imagePath="/projects-images/cronos.png"
                                    projectLink="https://github.com/Idov31/Cronos" projectName="Cronos"
                                    description="Cronos is a sleep obfuscation technique leveraging waitable timers to evade
                                    memory scanners (PE-Sieve, Moneta, etc.)"/>
                    </div>

                    <div className="lg:flex lg:flex-row">
                        <ProjectBox imagePath="/projects-images/venom.png"
                                    projectLink="https://github.com/Idov31/Venom" projectName="Venom"
                                    description="Venom is a library that performing evasive communication using stolen
                                    browser socket."/>

                        <ProjectBox imagePath="/projects-images/sandman.png"
                                    projectLink="https://github.com/Idov31/Sandman" projectName="Sandman"
                                    description="Sandman is a NTP based backdoor for operations in hardened networks."/>
                    </div>
                </div>
            </div>
        </div>
    );
}
