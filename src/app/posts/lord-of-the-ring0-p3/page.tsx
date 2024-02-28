"use client";

import SecondaryHeader, {BlogPrologue, BulletList, Code, InlineCode} from "@/components/BlogComponents";
import React from "react";
import StyledLink from "@/components/StyledLink";

export default function LordOfTheRing0P3() {
    const increaseIrql = `KIRQL prevIrql = KeGetCurrentIrql();
                        KeLowerIrql(PASSIVE_LEVEL);
                        KdPrint(("Print your string %ws.", myString));
                        KeRaiseIrql(prevIrql, &prevIrql);`;

    const myItem = `struct MyItem {
        int type;
        int price;
        WCHAR* ItemsName;
    }`;

    const execDeviceIoctl = `DeviceIoControl(hFile, IOCTL_DEMO,
    &myItem, sizeof(myItem),
    &myItem, sizeof(myItem), &returned, nullptr)`

    const ioctlFuncDefinition = `BOOL DeviceIoControl(
    [in] HANDLE hDevice,
    [in] DWORD dwIoControlCode,
    [in, optional] LPVOID lpInBuffer,
    [in] DWORD nInBufferSize,
    [out, optional] LPVOID lpOutBuffer,
    [in] DWORD nOutBufferSize,
    [out, optional] LPDWORD lpBytesReturned,
    [in, out, optional] LPOVERLAPPED lpOverlapped
    );`

    const irpSizeCheck = `auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

    if (size % sizeof(MyItem) != 0 || size == 0) {
        status = STATUS_INVALID_BUFFER_SIZE;
        break;
    }`
    const irpCheck = `...
    auto data = (MyItem*)Irp->AssociatedIrp.SystemBuffer;

    if (data->type < 0 || !data->ItemsName || data->price < 0) {
        status = STATUS_INVALID_PARAMETER;
        break;
    }
    ...`

    return (
        <div className="bg-bgInsideDiv p-6 rounded-xl h-full">
            <BlogPrologue title="Lord Of The Ring0 - Part 3 | Sailing to the land of the user (and debugging the ship)"
                          date="30.10.2022" projectLink="https://github.com/Idov31/Nidhogg"/>
            <div className="pt-4">
                <article>
                    <SecondaryHeader text="Prologue"/>
                    <div className="pt-4">
                        In the <StyledLink href="/posts/lord-of-the-ring0-p2" content="last blog post"
                                           textSize="text-md"/> we understood what it is a callback routine, how to get
                        basic information from user mode and for the finale created a driver that can block access to a
                        certain process. In this blog, we will dive into two of the most important things there are when
                        it comes to driver development: How to debug correctly, how to create good user-mode
                        communication and what lessons I learned during the development of Nidhogg so far.

                        <div className="pt-2">
                            This time, there will be no hands-on code writing but something more important - how to
                            solve and understand the problems that pop up when you develop kernel drivers.
                        </div>
                    </div>
                    <SecondaryHeader text="Debugging"/>
                    <div className="pt-4">
                        The way I see it, there are 3 approaches when it comes to debugging a kernel: The good, the
                        great and the hacky (of course you can combine them all and any of them).
                        I&apos;ll start by explaining every one of them, the benefits and the downsides.

                        <BulletList items={[
                            {
                                content: "The good: This method is for anyone because it doesn't require many " +
                                    "resources and is very" +
                                    "effective. All you need to do is to set the VM where you test your driver to " +
                                    "produce a crash dump " +
                                    "(you can leave the crash dump option to automatic) and make sure that in the " +
                                    "settings the" +
                                    "disable automatic deletion of memory dumps when the disk is low is checked or " +
                                    "you can find" +
                                    "yourself very confused to not find the crash dump when it should be generated. " +
                                    "Then, all you" +
                                    "have to do is to drag the crash dump back to your computer and analyze it. The " +
                                    "con of this" +
                                    "method is that sometimes you can see corrupted data and values that you don't " +
                                    "know how they got" +
                                    "there, but most of the time you will get a lot of information that can be very " +
                                    "helpful to traceback the source of the problem.",
                                linkContent: " (see how to produce a crash dump here)",
                                link: "https://learn.microsoft.com/en-us/windows/client-management/generate-kernel-o" +
                                    "r-complete-crash-dump"
                            },
                            {
                                content: "The great: This method is for those who have a good computer setup because " +
                                    "not everyone can" +
                                    "run it smoothly, to debug your VM I recommend following Microsoft's instructions" +
                                    "Then, all you have to do is put breakpoints in the right spots and do the " +
                                    "debugging we all love" +
                                    "to hate but gives the best results as you can track everything and see " +
                                    "everything in real-time." +
                                    "The con of this method is that it requires a lot of resources from the computer " +
                                    "and not everyone" +
                                    "(me included) has enough resources to open Visual Studio, run a VM and remote " +
                                    "debug it with WinDBG.",
                                linkContent: " (see how to set up a network debugging connection here)",
                                link: "https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/setting-up-a-network-debugging-connection"
                            },
                            {
                                content: "The hacky: I highly recommend not using this method alone. Like in every " +
                                    "type of program you" +
                                    "can print debugging messages with KdPrint and set up the VM to enable debugging" +
                                    "messages" +
                                    "and fire up DbgView to see your messages. " +
                                    "Make sure that if you are printing a string value lower the IRQL like so:",
                            }
                        ]}/>
                        <Code text={increaseIrql}/>

                        <div className="pt-2">
                            Because it lets you see what the values of the current variables are it is very useful, just
                            not
                            if you did something that causes the machine to crash, that&apos;s why I recommend combining it
                            with
                            either the crash dump option or the debugging option.
                        </div>
                        <div className="pt-2">
                            I won&apos;t do here a guide on how to use WinDBG because there are many
                            <StyledLink
                                href="https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/getting-started-with-windbg--kernel-mode-"
                                content=" great guides out there " textSize="text-md"/>
                            but I will add a word about it. The top commands that help me a lot during the process of
                            understanding what&apos;s wrong are:
                        </div>

                        <BulletList items={[
                            {
                                content: "!analyze -v: It lets WinDBG load the symbols, what is the error code and " +
                                    "most importantly the line in your source code that led to that BSOD."
                            },
                            {
                                content: "lm: This command shows you all the loaded modules at the time of the crash " +
                                    "and allows you to iterate them, their functions, etc."
                            },
                            {
                                content: "uf /D <address>: This command shows you the disassembly of a specific " +
                                    "address, so you can examine it."
                            }
                        ]}/>

                        After we now know the basics of how to debug a driver, let&apos;s dive into the main event: how to
                        properly exchange data with the user mode.
                    </div>
                    <SecondaryHeader text="Talking with the user-mode 102"/>
                    <div className="pt-4">
                        Last time we understood the different methods to send and get data from user mode, the basic
                        usage of IOCTLs and what IRPs are. But what happens when we want to send a list of different
                        variables? What happens if we want to send a file name, process name or something that isn&apos;t
                        just a number?

                        <div className="pt-2">
                            <b>DISCLAIMER: As I said before, in this series I&apos;ll be using the IOCTL method, so we will
                                address the problem using this method.</b>
                        </div>

                        <div className="pt-2">
                            To properly send data we can use the handly and trusty struct. What you need to do is to
                            define a data structure in both your user application and the kernel application for what
                            you are planning to send, for example:

                            <Code text={myItem}/>
                        </div>
                        <div className="pt-2">
                            And send it through the <InlineCode text="DeviceIoControl"/>:
                            <Code text={execDeviceIoctl}/>
                        </div>
                        <div className="pt-2">
                            But all of this we knew before, so what is new? As you noticed, I sent myItem twice and the
                            reason is in the definition of <InlineCode text="DeviceIoControl"/>:
                            <Code text={ioctlFuncDefinition}/>
                        </div>
                        <div className="pt-2">
                            We can define the IOCTL in a way that will allow the driver to both receive data and send
                            data, all we have to do is to define our IOCTL with the method type
                            <InlineCode text=" METHOD_BUFFERED"/> like so:
                            <Code text="#define IOCTL_DEMO CTL_CODE(0x8000, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)"/>
                        </div>
                        <div className="pt-1">
                            And now, <InlineCode text="SystemBuffer"/> is accessible for both writing and reading.
                        </div>
                        <div className="pt-2">
                            A quick reminder: <InlineCode text="SystemBuffer"/> is the way we can access the user data,
                            and is accessible to us through the IRP like so:
                            <Code text={`Irp->AssociatedIrp.SystemBuffer;`}/>
                        </div>

                        <div className="pt-2">
                            Now that we can access it there several questions remain: How can I write data to it without
                            causing BSOD? And how can I verify that I get the type that I want? What if I want to send
                            or receive a list of items and not just one?
                        </div>
                        <div className="pt-2">
                            The second question is easy to answer and is already shown up in the previous blog post:
                            <Code text={irpSizeCheck}/>
                        </div>
                        <div className="pt-2">
                            This is a simple yet effective test but isn&apos;t enough, that is why we also need to verify
                            every value we want to use:
                            <Code text={irpCheck}/>
                        </div>
                        <div className="pt-2">
                            This is just an example of checks that need to be done when accessing user mode data, and
                            everything that comes or returns to the user should be taken care of with extreme caution.
                        </div>
                        <div className="pt-2">
                            Writing data back to the user is fairly easy like in user mode, the hard part comes when you
                            want to return a list of items but don&apos;t want to create an entirely new structure just for
                            it. Microsoft themselves solved this in a pretty strange-looking yet effective way,
                            you can see it in several WinAPIs for example when iterating a process or modules and there
                            are two approaches:
                        </div>
                        <div className="pt-2">
                            The first one will be sending each item separately and when the list ends send null. The
                            second method is sending first the number of items you are going to send and then sending
                            them one by one. I prefer the second method but you can do whatever works for you.
                        </div>
                    </div>
                    <SecondaryHeader text="Conclusion"/>
                    <div className="pt-4">
                        This time, it was a relatively short blog post but very important for anyone that wants to write
                        a kernel mode driver correctly and learn to solve their problems.

                        <div className="pt-2">
                            In this blog, we learned how to debug a kernel driver and how to properly exchange data
                            between
                            our kernel driver to the user mode. In the next blog, we will understand the power of
                            callbacks
                            and learn about the different types that are available to us.
                        </div>

                        <div className="pt-2">
                            I hope that you enjoyed the blog and I&apos;m available on <StyledLink
                            href="https://twitter.com/Idov31" content="X (Twitter)" textSize="text-md"/>, <StyledLink
                            href="https://t.me/idov31" content="Telegram" textSize="text-md"/> and by <StyledLink
                            href="mailto:idov3110@gmail.com" content="mail" textSize="text-md"/> to hear what you think
                            about it!
                        </div>

                        <div className="pt-2">
                            This blog series is following my learning curve of kernel mode development and if you
                            like
                            this blog post you can check out Nidhogg on <StyledLink
                            href="https://github.com/idov31/Nidhogg" content="Github" textSize="text-md"/>.
                        </div>
                    </div>
                </article>
            </div>
        </div>
    );
}