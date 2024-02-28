"use client";

import SecondaryHeader, {BlogPrologue, BulletList, Code, InlineCode} from "@/components/BlogComponents";
import React from "react";
import StyledLink from "@/components/StyledLink";

export default function LordOfTheRing0P1() {
    const basicKernelDriver = `#include <ntddk.h>

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = MyUnload;
    KdPrint(("Hello World!\\n"));
    return STATUS_SUCCESS;
}

void MyUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    KdPrint(("Goodbye World!\\n"));
}`;

    const driverObjectDef = `typedef struct _DRIVER_OBJECT {
    CSHORT             Type;
    CSHORT             Size;
    PDEVICE_OBJECT     DeviceObject;
    ULONG              Flags;
    PVOID              DriverStart;
    ULONG              DriverSize;
    PVOID              DriverSection;
    PDRIVER_EXTENSION  DriverExtension;
    UNICODE_STRING     DriverName;
    PUNICODE_STRING    HardwareDatabase;
    PFAST_IO_DISPATCH  FastIoDispatch;
    PDRIVER_INITIALIZE DriverInit;
    PDRIVER_STARTIO    DriverStartIo;
    PDRIVER_UNLOAD     DriverUnload;
    PDRIVER_DISPATCH   MajorFunction[IRP_MJ_MAXIMUM_FUNCTION + 1];
} DRIVER_OBJECT, *PDRIVER_OBJECT;`;

    const loadDrv = `sc create DriverName type= kernel binPath= C:\\Path\\To\\Driver.sys
sc start DriverName`;

    return (
        <div className="bg-bgInsideDiv p-6 rounded-xl h-full">
            <BlogPrologue title="Lord Of The Ring0 - Part 1 | Introduction"
                          date="14.07.2022" projectLink="https://github.com/Idov31/Nidhogg"/>
            <div className="pt-4">
                <article>
                    <SecondaryHeader text="Prologue"/>
                    <div className="pt-4">
                        This blog post series isn&apos;t a thing I normally do, this will be more like a journey that I
                        document during the development of my project <StyledLink
                        href="https://github.com/idov31/Nidhogg" content="Nidhogg" textSize="text-md"/>. In this series
                        of blogs (which I don&apos;t know how long will it be), I&apos;ll write about difficulties I encountered
                        while developing Nidhogg and tips & tricks for everyone who wants to start creating a stable
                        kernel mode driver in 2022.

                        <div className="pt-2">
                            This series will be about WDM type of kernel drivers, developed in VS2019. To install it,
                            you can follow the guide in <StyledLink
                            href="https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk"
                            content="MSDN" textSize="text-md"/>. I highly recommend that you test EVERYTHING in a
                            virtual machine to avoid crashing your computer.
                        </div>

                        <div className="pt-2">
                            Without further delays - Let&apos;s start!
                        </div>
                    </div>

                    <SecondaryHeader text="Kernel Drivers In 2022"/>
                    <div className="pt-4">
                        The first question you might ask yourself is: How can kernel driver help me in 2022? There are a
                        lot of 1337 things that I can do for the user mode without the pain of developing and
                        consistently crashing my computer.

                        <div className="pt-2">
                            From a red team perspective, I think that there are several things that a kernel driver can
                            give that user mode can&apos;t.
                        </div>

                        <BulletList items={[
                            {
                                content: "Being an efficient backdoor with extremely evasive persistency."
                            },
                            {
                                content: "Do highly privileged operations without the dependency of LPE exploit or " +
                                    "privileged users."
                            },
                            {
                                content: "Easily evade AV / EDR hooks."
                            },
                            {
                                content: "Be able to hide your agent without suspicious user-mode hooks."
                            }
                        ]}/>

                        <div className="pt-2">
                            From a blue team perspective, you can log more events and block suspicious operations with
                            methods you won&apos;t be able to do in the user mode.

                            <BulletList items={[
                                {
                                    content: "Create a driver to monitor and log specific events (like " +
                                        "specially crafted Sysmon to meet your organization's needs."
                                },
                                {
                                    content: "Create kernel mode hooks to find advanced rootkits and malware."
                                },
                                {
                                    content: "Provide kernel mode protection to your blue agents (such as OSQuery, " +
                                        "Wazuh, etc.)."
                                }
                            ]}/>
                        </div>

                        <div className="pt-2">
                            <b>NOTE: This blog series will focus more on the red team part but I&apos;ll also add the blue
                                team perspective as one affects the other.</b>
                        </div>
                        <SecondaryHeader text="Basic driver structure"/>
                        <div className="pt-4">
                            Like any good programmer, we will start with creating a basic driver to print famous words
                            with
                            an explanation of the basics.
                        </div>
                        <Code text={basicKernelDriver}/>

                        <div className="pt-2">
                            This simple driver will print &quot;Hello World!&quot; and &quot;Goodbye World!&quot; when
                            it&apos;s loaded and
                            unloaded.
                            Since the parameter <InlineCode text="RegistryPath"/> is not used, we can use
                            <InlineCode text=" UNREFERENCED_PARAMETER"/> to optimize the variable.
                        </div>

                        <div className="pt-2">
                            Every driver needs to implement at least the two functions mentioned above.
                        </div>

                        <div className="pt-2">
                            The <InlineCode text="DriverEntry"/> is the first function that is called when the driver is
                            loaded and it is very much like the main function for user-mode programs, except it gets two
                            parameters:
                        </div>
                        <BulletList items={[
                            {
                                content: "DriverObject: A pointer to the driver object."
                            },
                            {
                                content: "RegistryPath: A pointer to a UNICODE_STRING structure that contains the path to " +
                                    "the driver's registry key."
                            }
                        ]}/>

                        <div className="pt-2">
                            The <InlineCode text="DriverObject"/> is an important object that will serve us a lot in the
                            future, its definition is:
                        </div>
                        <Code text={driverObjectDef}/>

                        <div className="pt-2">
                            But I&apos;d like to focus on the <InlineCode text="MajorFunction"/>: This is an array of
                            important
                            functions that the driver can implement for IO management in different ways
                            (direct or with IOCTLs), handling IRPs and more.
                        </div>

                        <div className="pt-2">
                            We will use it for the next part of the series but for now, keep it in mind.
                            (A little tip: Whenever you encounter a driver and you want to know what it is doing make
                            sure
                            to check out the functions inside the <InlineCode text="MajorFunction"/> array).
                        </div>
                        <div className="pt-2">
                            To finish the most basic initialization you will need to do one more thing - define the
                            <InlineCode text=" DriverUnload"/> function. This function will be responsible to stop
                            callbacks
                            and free any memory that was allocated.
                        </div>
                        <div className="pt-2">
                            When you finish your driver initialization you need to return an <InlineCode
                            text="NTSTATUS "/>
                            code, this code will be used to determine if the driver will be loaded or not.
                        </div>
                    </div>

                    <SecondaryHeader text="Testing a driver"/>
                    <div className="pt-4">
                        If you tried to copy & paste and run the code above, you might have noticed that it&apos;s not
                        working.

                        <div className="pt-2">
                            By default, Windows does not allow loading self-signed drivers, and surely not unsigned
                            drivers, this was created to make sure that a user won&apos;t load a malicious driver and by that
                            give an attacker even more persistence and privileges on the attacked machine.
                        </div>

                        <div className="pt-2">
                            Luckily, there is a way to bypass this restriction for testing purposes, to do this run the
                            following command from an elevated cmd:
                        </div>

                        <div className="pt-2">
                            <InlineCode text="bcdedit /set testsigning on"/>
                        </div>
                        <div className="pt-2">
                            After that restart, your computer and you should be able to load the driver.
                        </div>

                        <div className="pt-2">
                            To test it out, you can use <StyledLink
                            href="https://docs.microsoft.com/en-us/sysinternals/downloads/debugview" content="Dbgview "
                            textSize="text-md"/>
                            to see the output (don&apos;t forget to compile to debug to see the
                            <InlineCode text=" KdPrint"/>&apos;s output). To load the driver, you can use the following
                            command:
                        </div>
                        <Code text={loadDrv} language={"console"}/>

                        <div className="pt-2">
                            And to unload it:
                        </div>
                        <div className="pt-2">
                            <InlineCode text="sc stop DriverName"/>
                        </div>

                        <div className="pt-2">
                            You might ask yourself now, how an attacker can deploy a driver? This can be done in several
                            ways:
                        </div>

                        <BulletList items={[
                            {
                                content: "The attacker has found/generated a certificate (the expiration date " +
                                    "doesn't matter)."
                            },
                            {
                                content: "The attacker has allowed test signing (just like we did now)."
                            },
                            {
                                content: "The attacker has a vulnerable driver with 1-day that allows loading drivers."
                            },
                            {
                                content: "The attacker has a zero-day that allows load drivers."
                            }
                        ]}/>

                        <div className="pt-2">
                            Just not so long ago when <StyledLink
                            href="https://www.bleepingcomputer.com/news/security/nvidia-data-breach-exposed-credentials-of-over-71-000-employees/"
                            content=" Nvidia was breached" textSize="text-md"/> a signature was leaked and used by
                            <StyledLink
                                href="https://securityonline.info/nvidias-leaked-code-signing-certificate-is-used-by-hackers-to-sign-malware/"
                                content=" threat actors" textSize="text-md"/>.
                        </div>
                    </div>

                    <SecondaryHeader text="Resources"/>
                    <div className="pt-4">
                        When we will continue to dive into the series, I will use a lot of references from the following
                        amazing resources:

                        <BulletList items={[
                            {
                                content: "Windows Kernel Programming."
                            },
                            {
                                content: "Windows Internals Part 7."
                            },
                            {
                                content: "MSDN (I know I said amazing, I lied here)."
                            }
                        ]}/>

                        <div className="pt-2">
                            And you can check out the following repositories for drivers examples:
                        </div>

                        <BulletList items={[
                            {
                                content: "",
                                linkContent: "Windows Kernel Programming's Examples",
                                link: "https://github.com/zodiacon/windowskernelprogrammingbook"
                            },
                            {
                                content: "",
                                linkContent: "Microsoft's Example Drivers",
                                link: "https://github.com/microsoft/Windows-driver-samples"
                            }
                        ]}/>
                    </div>

                    <SecondaryHeader text="Conclusion"/>
                    <div className="pt-4">
                        This blog post may be short but is the start of the coming series of blog posts about kernel
                        drivers and rootkits specifically. Another one, more detailed, will come out soon!

                        <div className="pt-2">
                            I hope that you enjoyed the blog and I&apos;m available on <StyledLink
                            href="https://twitter.com/Idov31" content="X (Twitter)" textSize="text-md"/>, <StyledLink
                            href="https://t.me/idov31" content="Telegram" textSize="text-md"/> and by <StyledLink
                            href="mailto:idov3110@gmail.com" content="mail" textSize="text-md"/> to hear what you think
                            about it!
                        </div>

                        <div className="pt-2">
                            This blog series is following my learning curve of kernel mode development and if you
                            like this blog post you can check out Nidhogg on <StyledLink
                            href="https://github.com/idov31/Nidhogg" content="Github" textSize="text-md"/>.
                        </div>
                    </div>
                </article>
            </div>
        </div>
    );
}