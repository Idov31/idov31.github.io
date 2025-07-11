"use client";

import SecondaryHeader, {BlogPrologue, BulletList, InlineCode} from "@/components/BlogComponents";
import React from "react";
import StyledLink from "@/components/StyledLink";
import Image from "next/image";

export default function ListUdpConnections() {
    return (
        <div className="bg-bgInsideDiv p-6 rounded-xl h-full">
            <BlogPrologue title="UdpInspector - Getting active UDP connections without sniffing"
                          date="19.08.2021" projectLink="https://github.com/Idov31/UdpInspector"/>
            <div className="pt-4">
                <article>
                    <SecondaryHeader text="UdpInspector - Getting active UDP connections without sniffing"/>
                    <div className="drop-caps pt-4">
                        Many times I&apos;ve wondered how comes that there are no tools to get active UDP connections.
                        Of course, you can always sniff with Wireshark or any other tool of your choosing but, why
                        netstat doesn&apos;t have it built in? That is the point that I went on a quest to investigate the
                        matter. Naturally, I started with MSDN to read more about what I could get about UDP
                        connections, and that is the moment when I found these two functions:

                        <BulletList items={[
                            {
                                content: "",
                                linkContent: "GetUdpTable",
                                link: "https://docs.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getudptable"
                            },
                            {
                                content: "",
                                linkContent: "GetExtendedUdpTable",
                                link: "https://docs.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedudptable"
                            }
                        ]}/>

                        <div className="pt-2">
                            So, I started to look at the struct they returned and saw a struct named <StyledLink
                            href="https://docs.microsoft.com/en-us/windows/win32/api/udpmib/ns-udpmib-mib_udptable"
                            content="MIB_UDPTABLE" textSize="text-md"/>.
                        </div>
                        <Image src="/post-images/list-udp-connections/udptable.png" alt="udptable" height="150"
                               width="350"/>

                        <div className="pt-2">
                            Sadly and unsurprisingly it gave no useful information but remember this struct - It will be
                            used in the future. This is when I started to check another path - Reverse Engineering
                            netstat.
                        </div>
                        <div className="pt-2">
                            I will tell you that now - It wasn&apos;t helpful at all, but I did learn about a new
                            undocumented
                            function - Always good to know!
                        </div>
                        <div className="pt-2">
                            When I opened netstat I searched for the interesting part - How it gets the UDP connections?
                            Maybe it uses a special function that would help me as well.
                        </div>
                        <Image src="/post-images/list-udp-connections/netstat1.png" alt="netstat-udp-function"
                               height="50" width="175"/>

                        <div className="pt-2">
                            After locating the area where it calls to get the UDP connections I saw that weird function:
                            <InlineCode text=" InternalGetUdpTableWithOwnerModule"/>.
                        </div>
                        <Image src="/post-images/list-udp-connections/netstat2.png"
                               alt="InternalGetUdpTableWithOwnerModule" height="150" width="350"/>

                        <div className="pt-2">
                            After a quick check on google, I saw that it won&apos;t help me, there isn&apos;t much documentation
                            about it. After I realized that it won&apos;t help I went back to the source: The <InlineCode
                            text="GetExtendedUdpTable"/> function.
                        </div>
                        <div className="pt-2">
                            After rechecking it I found out that it gives also the PIDs of the processes that
                            communicate in
                            UDP. That was the moment when I understood and built a baseline of what would be my first
                            step
                            in solving the problem: <InlineCode text="GetExtendedUdpTable"/> and then get the socket
                            out of the process. But it wasn&apos;t enough.
                        </div>
                        <div className="pt-2">
                            I needed somehow to iterate and locate the socket that the process holds. After opening
                            Process Explorer I saw something unusual - I expected to see something like <InlineCode
                            text="\device\udp"/> or <InlineCode text="\device\tcp"/> but I saw instead a weird
                            <InlineCode text=" \device\afd"/>.
                        </div>
                        <div className="pt-1">
                            After we duplicated the socket we are one step from the entire solution: What is left is to
                            extract the remote address and port. Confusingly, the function that needs to be used is
                            <InlineCode text=" getsockname"/> and not <InlineCode text="getpeername"/> - Although the
                            <InlineCode text=" getpeername"/> function theoretically should be used.
                        </div>
                        <div className="pt-2">
                            Summing up, these are the steps that you need to apply to do it:
                        </div>

                        <BulletList items={[
                            {
                                content: "Get all the PIDs that are currently communicating via UDP " +
                                    "(via GetExtendedUdpTable)"
                            },
                            {
                                content: "Enumerate the PIDs and extract their handles table (NtQueryInformation, " +
                                    "NtQueryObject)"
                            },
                            {
                                content: "Duplicate the handle to the socket (identified with \\Device\\Afd)"
                            },
                            {
                                content: "Extract from the socket the remote address"
                            }
                        ]} />
                    </div>
                </article>
            </div>
        </div>
    );
}