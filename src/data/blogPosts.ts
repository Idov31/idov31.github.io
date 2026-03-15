export type BlogPostSummary = {
    href: string;
    headerContent: string;
    subHeaderContent: string;
    imagePath: string;
    imageAlt: string;
    imageWidth: number;
    imageHeight: number;
    postContent: string;
    sub?: boolean;
};

export const blogPosts: BlogPostSummary[] = [
    {
        href: "/posts/hypervisor-based-defense",
        headerContent: "Hypervisor Based Defense",
        subHeaderContent: "14 Mar 2026",
        imagePath: "/post-images/hypervisor-based-defense.png",
        imageAlt: "hypervisor-based-defense",
        imageWidth: 135,
        imageHeight: 51,
        postContent: "Hey there, it has been a \"little\" while since I published my last post. After scrapping and rewriting multiple ideas, I decided to write something a bit different from my previous posts. This post contains technical information, but I also wanted to share my thoughts after working on a hypervisor project for more than a year.",
    },
    {
        href: "/posts/lord-of-the-ring0-p6",
        headerContent: "Lord Of The Ring0 — Part 6 | Conclusion",
        subHeaderContent: "31 Mar 2024",
        imagePath: "/post-images/lotr06.png",
        imageAlt: "lotr06",
        imageWidth: 135,
        imageHeight: 51,
        postContent: "In the last blog post, we learned about two common hooking methods (IRP Hooking and SSDT Hooking) and two different injection techniques from the kernel to the user mode for both shellcode and DLL (APC and CreateThread) with code snippets and examples from Nidhogg. In this blog post, we will write a simple driver that is capable of bypassing AMSI to demonstrate patching usermode memory from the kernel, go through credential dumping process from the kernel and finish with tampering various kernel callbacks as an example for patching kernel mode memory and last but not least - the final words and conclusion of this series. In the last blog post, we learned about process hiding and got into the internals of some of the most dangerous patching methods from the kernel.",
        sub: false,
    },
    {
        href: "/posts/lord-of-the-ring0-p5",
        headerContent: "Lord Of The Ring0 — Part 5 | Saruman's Manipulation",
        subHeaderContent: "19 Jul 2023",
        imagePath: "/post-images/lotr05.png",
        imageAlt: "lotr05",
        imageWidth: 135,
        imageHeight: 51,
        postContent: "In the last blog post, we learned about the different types of kernel callbacks and created our registry protector driver. In this blog post, I'll explain two common hooking methods (IRP Hooking and SSDT Hooking) and two different injection techniques from the kernel to the user mode for both shellcode and DLL (APC and CreateThread) with code snippets and examples from Nidhogg. While there are couple of methods to perform operations from kernel mode on user mode processes, in this part I will focus on one of the most common methods that allow it with ease - KeStackAttachProcess.",
    },
    {
        href: "/posts/lord-of-the-ring0-p4",
        headerContent: "Lord Of The Ring0 — Part 4 | The Call Back Home",
        subHeaderContent: "24 Feb 2023",
        imagePath: "/post-images/lotr04.png",
        imageAlt: "lotr04",
        imageWidth: 135,
        imageHeight: 51,
        postContent: "In the last blog post, we learned some debugging concepts, understood what is IOCTL how to handle it and started to learn how to validate the data that we get from the user mode - data that cannot be trusted and a handling mistake can cause a blue screen of death. In this blog post, I'll explain the different types of callbacks and we will write another driver to protect registry keys. We started to talk about this subject in the 2nd part, so if you haven't read it yet read it here and come back as this blog is based on the knowledge you have learned in the previous ones.",
    },
    {
        href: "/posts/cronos-sleep-obfuscation",
        headerContent: "timeout /t 31 && start evil.exe",
        subHeaderContent: "06 Nov 2022",
        imagePath: "/post-images/cronos-sleep-obf.png",
        imageAlt: "cronos-sleep-obf",
        imageWidth: 135,
        imageHeight: 51,
        postContent: "Cronos is a new sleep obfuscation technique co-authored by idov31 and yxel. It is based on 5pider's Ekko and like it, it encrypts the process image with RC4 encryption and evades memory scanners by also changing memory regions permissions from RWX to RW back and forth. In this blog post, we will cover Cronos specifically and sleep obfuscation techniques in general and explain why we need them and the common ground of any sleep obfuscation technique.",
    },
    {
        href: "/posts/lord-of-the-ring0-p3",
        headerContent: "Lord Of The Ring0 — Part 3 | Sailing to the Land of the User",
        subHeaderContent: "30 Oct 2022",
        imagePath: "/post-images/lotr03.png",
        imageAlt: "lotr03",
        imageWidth: 135,
        imageHeight: 51,
        postContent: "In the last blog post we understood what it is a callback routine, how to get basic information from user mode and for the finale created a driver that can block access to a certain process. In this blog, we will dive into two of the most important things there are when it comes to driver development: How to debug correctly, how to create good user-mode communication and what lessons I learned during the development of Nidhogg so far. This time, there will be no hands-on code writing but something more important - how to solve and understand the problems that pop up when you develop kernel drivers.",
    },
    {
        href: "/posts/lord-of-the-ring0-p2",
        headerContent: "Lord Of The Ring0 — Part 2 | A Tale of Routines, IOCTLs and IRPs",
        subHeaderContent: "04 Aug 2022",
        imagePath: "/post-images/lotr02.png",
        imageAlt: "lotr02",
        imageWidth: 135,
        imageHeight: 51,
        postContent: "In the last blog post, we had an introduction to kernel development and what are the difficulties when trying to load a driver and how to bypass it. In this blog, I will write more about callbacks, how to start writing a rootkit and the difficulties I encountered during my development of Nidhogg. As I promised to bring both defensive and offensive points of view, we will create a driver that can be used for both blue and red teams - A process protector driver.",
    },
    {
        href: "/posts/lord-of-the-ring0-p1",
        headerContent: "Lord Of The Ring0 — Part 1 | Introduction",
        subHeaderContent: "14 Jul 2022",
        imagePath: "/post-images/lotr0.png",
        imageAlt: "lotr01",
        imageWidth: 135,
        imageHeight: 51,
        postContent: "This blog post series isn't a thing I normally do, this will be more like a journey that I document during the development of my project Nidhogg. In this series of blogs (which I don't know how long will it be), I'll write about difficulties I encountered while developing Nidhogg and tips & tricks for everyone who wants to start creating a stable kernel mode driver in 2022. This series will be about WDM type of kernel drivers, developed in VS2019.",
    },
    {
        href: "/posts/rust101-rustomware",
        headerContent: "Rust 101 — Let's Write Rustomware",
        subHeaderContent: "07 May 2022",
        imagePath: "/post-images/rustsomware.png",
        imageAlt: "rustsomware",
        imageWidth: 135,
        imageHeight: 51,
        postContent: "When I first heard about Rust, my first reaction was \"Why?\". The language looked to me as a \"wannabe\" to C and I didn't understand why it is so popular. I started to read more and more about this language and began to like it.",
    },
    {
        href: "/posts/function-stomping",
        headerContent: "The Good, The Bad and The Stomped Function",
        subHeaderContent: "28 Jan 2022",
        imagePath: "/post-images/function-stomping.png",
        imageAlt: "function-stomping",
        imageWidth: 135,
        imageHeight: 51,
        postContent: "When I first heard about ModuleStomping I was charmed since it wasn't like any other known injection method. Every other injection method has something in common: They use VirtualAllocEx to allocate a new space within the process, and ModuleStomping does something entirely different: Instead of allocating new space in the process, it stomps an existing module that will load the malicious DLL. After I saw that I started to think: How can I use that to make an even more evasive change that won't trigger the AV/EDR or won't be found by the injection scanner?",
    },
    {
        href: "/posts/list-udp-connections",
        headerContent: "UdpInspector — Getting Active UDP Connections Without Sniffing",
        subHeaderContent: "19 Aug 2021",
        imagePath: "/post-images/udpinspect.png",
        imageAlt: "udpinspect",
        imageWidth: 135,
        imageHeight: 51,
        postContent: "Many times I've wondered how comes that there are no tools to get active UDP connections. Of course, you can always sniff with Wireshark or any other tool of your choosing but, why netstat doesn't have it built in? That is the point that I went on a quest to investigate the matter.",
    },
];