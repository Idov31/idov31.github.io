"use client";

import SecondaryHeader, {BlogPrologue, BulletList, Code, InlineCode} from "@/components/BlogComponents";
import React from "react";
import StyledLink from "@/components/StyledLink";
import Image from "next/image";

export default function FunctionStomping() {
    const getFunctionBase = ` // Getting the module name.
    if (GetModuleFileNameEx(procHandle, currentModule, currentModuleName, MAX_PATH -
    sizeof(wchar_t)) == 0) {
        std::cerr << "[-] Failed to get module name: " << GetLastError() << std::endl;
        continue;
    }

    // Checking if it is the module we seek.
    if (StrStrI(currentModuleName, moduleName) != NULL) {
        functionBase = (BYTE *)GetProcAddress(currentModule, functionName);
        break;
    }`;

    const pocDevelopment = `// Changing the protection to PAGE_READWRITE for the shellcode.
if (!VirtualProtectEx(procHandle, functionBase, sizeToWrite, PAGE_READWRITE, &oldPermissions)) {
    std::cerr << "[-] Failed to change protection: " << GetLastError() << std::endl;
    CloseHandle(procHandle);
    return -1;
}

SIZE_T written;

// Writing the shellcode to the remote address.
if (!WriteProcessMemory(procHandle, functionBase, shellcode, sizeof(shellcode), &written)) {
    std::cerr << "[-] Failed to overwrite function: " << GetLastError() << std::endl;
    VirtualProtectEx(procHandle, functionBase, sizeToWrite, oldPermissions, &oldPermissions);
    CloseHandle(procHandle);
    return -1;
}`;
    return (
        <div className="bg-bgInsideDiv p-6 rounded-xl h-full">
            <BlogPrologue title="The Good, The Bad and The Stomped Function"
                          date="28.01.2022" projectLink="https://github.com/Idov31/FunctionStomping"/>
            <div className="pt-4">
                <article>
                    <SecondaryHeader text="Introduction"/>
                    <div className="pt-4">
                        When I first heard about <InlineCode text="ModuleStomping"/> I was charmed since it wasn&apos;t like
                        any other known
                        injection method.

                        <div className="pt-2">
                            Every other injection method has something in common: They use <InlineCode
                            text="VirtualAllocEx"/> to allocate a new space within the process, and <InlineCode
                            text="ModuleStomping"/> does something entirely different: Instead of allocating new space
                            in the process, it stomps an existing module that will load the malicious DLL.
                        </div>

                        <div className="pt-2">
                            After I saw that I started to think: How can I use that to make an even more evasive change
                            that won&apos;t trigger the AV/EDR or won&apos;t be found by the injection scanner?
                        </div>
                        <div className="pt-2">
                            The answer was pretty simple: Stomp a single function! At the time I thought it is a matter
                            of hours to make this work, but I know now that it took me a little while to solve all the
                            problems.
                        </div>
                    </div>

                    <SecondaryHeader text="How does a simple injection look like"/>
                    <div className="pt-4">
                        The general purpose of any injection is to evade anti-viruses and EDRs and be able to deliver or
                        execute malware.

                        <div className="pt-2">
                            For all of the injection methods, you need to open a process with <InlineCode
                            text="PROCESS_ALL_ACCESS"/> permission (or a combination of permissions that allow you to
                            spawn a thread, write and read the process&apos; memory).
                        </div>
                        <div className="pt-2">
                            since the injector needs to perform high-privilege operations such as writing to the memory
                            of
                            the process and executing the shellcode remotely. To be able to get <InlineCode
                            text="PROCESS_ALL_ACCESS"/> you either need that the injected process will run under your
                            user&apos;s context or need to have a high-privileged user running in a high-privileged context
                            (you can read more about UAC and what is a low privileged and high-privileged admin in
                            <StyledLink
                                href="https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works"
                                content=" MSDN" textSize="text-md"/>) or the injected process is a process that you
                            spawned under your process and therefore have all access.
                        </div>
                        <div className="pt-2">
                            After we obtain a valid handle with the right permissions we need to allocate space to the
                            shellcode within the remote process virtual memory with <InlineCode text="VirtualAllocEx"/>.
                            That gives us the space and the address we need for the shellcode to be written. After we
                            have a
                            page with the right permissions and enough space, we can use <InlineCode
                            text="WriteProcessMemory"/> to write the shellcode into the remote process.
                        </div>

                        <div className="pt-2">
                            Now, all that&apos;s left to do is to call <InlineCode text="CreateRemoteThread"/> with the
                            shellcode&apos;s address (that we got from the <InlineCode text="VirtualAllocEx"/>) to spawn our
                            shellcode in the other process.
                        </div>
                        <div className="pt-2">
                            To summarize:
                            <div className="flex items-center justify-center justify-items-center">
                                <Image src="/post-images/function-stomping/shellcode_injection.png"
                                       alt="shellcode_injection" width="150" height="50"/>
                            </div>
                        </div>
                    </div>

                    <SecondaryHeader text="Research - How and why FunctionStomping works?"/>
                    <div className="pt-4">
                        For the sake of the POC, I chose to target <InlineCode text="User32.dll"/> and <InlineCode
                        text="MessageBoxW"/>. But, unlike the regular way of using <InlineCode text="GetModuleHandle"/>,
                        I needed to do it remotely. For that, I used the <InlineCode text="EnumProcessModules "/>
                        function:

                        <div className="flex items-center justify-center justify-items-center">
                            <Image src="/post-images/function-stomping/enum_process_modules.png"
                                   alt="enum_process_modules" width="300" height="100"/>
                        </div>

                        <div className="pt-2">
                            It looks like a very straightforward function and now all I needed to do is to use the good
                            old <InlineCode text="GetProcAddress"/>. The implementation was pretty simple: Use
                            <InlineCode text=" GetModuleFileName"/> to get the module&apos;s name out of the handle and then
                            if it is the module we seek (currently <InlineCode text="User32.dll"/>). If it is, just use
                            <InlineCode text=" GetProcAddress"/> and get the function&apos;s base address.
                        </div>
                        <Code text={getFunctionBase}/>

                        <div className="pt-2">
                            But it didn&apos;t work. I sat by the computer for a while, staring at the valid module handle I
                            got and couldn’t figure out why I could not get the function pointer. At this point, I went
                            back to MSDN and read again the description, and one thing caught my eye:
                        </div>
                        <div className="flex items-center justify-center justify-items-center">
                            <Image src="/post-images/function-stomping/module_permissions.png" alt="module_permissions"
                                   width="600" height="200"/>
                        </div>

                        <div className="pt-2">
                            Well... That explains some things. I searched more about this permission and found this
                            explanation:
                        </div>
                        <div className="flex items-center justify-center justify-items-center">
                            <Image src="/post-images/function-stomping/load_library_as_datafile.png"
                                   alt="load_library_as_datafile" width="600" height="200"/>
                        </div>

                        <div className="pt-2">
                            That was very helpful to me because at this moment I knew why even when I have a valid
                            handle, I
                            cannot use <InlineCode text="GetProcAddress"/>! I decided to change <InlineCode
                            text="User32.dll"/> and <InlineCode text="MessageBoxW"/> to other modules and functions:
                            <InlineCode text=" Kernel32.dll"/> and <InlineCode text="CreateFileW"/>.
                        </div>

                        <div className="pt-2">
                            If you are wondering why <InlineCode text="Kernel32.dll"/> and not another DLL, the reason
                            is that <InlineCode text="Kernel32.dll"/> is always loaded with any file (you can read more
                            about it in the great Windows Internals books) and therefore a reliable target.
                        </div>

                        <div className="pt-2">
                            And now all that&apos;s left is to write the POC.
                        </div>
                    </div>

                    <SecondaryHeader text="POC Development - Final stages"/>
                    <div className="pt-4">
                        The final step is similar to any other injection method but with one significant change: We need
                        to use <InlineCode text="VirtualProtectEx"/> with the base address of our function. Usually,
                        in injections, we give set the address parameter to NULL and get back the address that is mapped
                        for us, but since we want to overwrite an existing function we need to give the base address.

                        <div className="pt-2">
                            After <InlineCode text="WriteProcessMemory"/> is executed, the function is successfully
                            stomped!
                        </div>
                        <Code text={pocDevelopment}/>

                        <div className="pt-2">
                            At first, I used <InlineCode text="PAGE_EXECUTE_READWRITE"/> permission to execute the
                            shellcode but it is problematic (Although even with the <InlineCode
                            text="PAGE_EXECUTE_READWRITE"/> flag anti-viruses and hollows-hunter still failed to detect
                            it - I wanted to use something else).
                        </div>
                        <div className="pt-2">
                            Because of that, I checked if there is any other permission that can help with what I
                            wanted: To be able to execute the shellcode and still be undetected. You may ask yourself:
                            &quot;Why not just use <InlineCode text="PAGE_EXECUTE_READ"/>?&quot;
                        </div>
                        <div className="pt-2">
                            I wanted to create a single POC and be able to execute any kind of shellcode: Whether it
                            writes
                            to itself or not, and I&apos;m proud to say that I found a solution for that.
                        </div>
                        <div className="pt-2">
                            I researched further about the available page permissions and one caught my eye:
                            <InlineCode text=" PAGE_EXECUTE_WRITECOPY"/>.
                        </div>
                        <div className="flex items-center justify-center justify-items-center pt-2">
                            <Image src="/post-images/function-stomping/page_execute_write_copy.png"
                                   alt="page_execute_write_copy" height="200" width="600"/>
                        </div>
                        <div className="pt-2">
                            It looks like it gives read, write and execute permissions without actually using
                            <InlineCode text=" PAGE_EXECUTE_READWRITE"/>. I wanted to dig a little deeper into this and
                            found an article by CyberArk that explains more about this permission and it looked like the
                            fitting solution.
                        </div>
                        <div className="pt-2">
                            To conclude, the UML of this method looks like that:
                        </div>
                        <div className="flex items-center justify-center justify-items-center pt-2">
                            <Image src="/post-images/function-stomping/function_stomping.png" alt="function_stomping"
                                   height="50" width="150"/>
                        </div>
                    </div>

                    <SecondaryHeader text="Detection"/>
                    <div className="pt-4">
                        Because many antiviruses failed to identify this shellcode injection technique as malicious I
                        added a YARA signature I wrote so you can import that to your defense tools.
                    </div>

                    <SecondaryHeader text="Acknowledgments" />
                    <div className="pt-4">
                        <BulletList items={[
                            {
                                content: "",
                                linkContent: "ModuleStomping",
                                link: "https://github.com/countercept/ModuleStomping"
                            },
                            {
                                content: "",
                                linkContent: "CyberArk's article",
                                link: "https://www.cyberark.com/resources/threat-research-blog/masking-malicious-memory-artifacts-part-iii-bypassing-defensive-scanners"
                            }
                        ]} />
                    </div>
                </article>
            </div>
        </div>
    );
}