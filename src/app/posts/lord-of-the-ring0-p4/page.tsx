"use client"

import React from "react";
import StyledLink from "@/components/StyledLink";
import SecondaryHeader, {BlogPrologue, BulletList, Code, InlineCode, ThirdHeader} from "@/components/BlogComponents";

export default function LordOfTheRing0P4() {
    const obCallbackRegistration = `typedef struct _OB_CALLBACK_REGISTRATION {
                        USHORT                    Version;
                        USHORT                    OperationRegistrationCount;
                        UNICODE_STRING            Altitude;
                        PVOID                     RegistrationContext;
                        OB_OPERATION_REGISTRATION *OperationRegistration;
    } OB_CALLBACK_REGISTRATION, *POB_CALLBACK_REGISTRATION;`
    const obOperationRegistration = ` typedef struct _OB_OPERATION_REGISTRATION {
                        POBJECT_TYPE                *ObjectType;
                        OB_OPERATION                Operations;
                        POB_PRE_OPERATION_CALLBACK  PreOperation;
                        POB_POST_OPERATION_CALLBACK PostOperation;
    } OB_OPERATION_REGISTRATION, *POB_OPERATION_REGISTRATION;`
    const obObjectType = `typedef struct _OBJECT_TYPE {
                            struct _LIST_ENTRY TypeList;
                            struct _UNICODE_STRING Name;
                            VOID* DefaultObject;
                            UCHAR Index;
                            ULONG TotalNumberOfObjects;
                            ULONG TotalNumberOfHandles;
                            ULONG HighWaterNumberOfObjects;
                            ULONG HighWaterNumberOfHandles;
                            struct _OBJECT_TYPE_INITIALIZER_TEMP TypeInfo;
                            struct _EX_PUSH_LOCK_TEMP TypeLock;
                            ULONG Key;
                            struct _LIST_ENTRY CallbackList;
    } OBJECT_TYPE, * POBJECT_TYPE;

    POBJECT_TYPE_TEMP ObjectTypeTemp = (POBJECT_TYPE_TEMP)*IoFileObjectType;
    ObjectTypeTemp->TypeInfo.SupportsObjectCallbacks = 1;`

    const createProcessNotifyRoutine = `void PcreateProcessNotifyRoutine(
                        [in] HANDLE ParentId,
                        [in] HANDLE ProcessId,
                        [in] BOOLEAN Create
    )`

    const createThreadNotifyRoutine = `void PcreateThreadNotifyRoutine(
                            [in] HANDLE ProcessId,
                            [in] HANDLE ThreadId,
                            [in] BOOLEAN Create
    )`

    const loadImageNotifyRoutine = `void PloadImageNotifyRoutine(
                            [in, optional] PUNICODE_STRING FullImageName,
                            [in] HANDLE ProcessId,
                            [in] PIMAGE_INFO ImageInfo
    )`

    const imageInfo = `typedef struct _IMAGE_INFO {
        union {
            ULONG Properties;
            struct {
                ULONG ImageAddressingMode : 8;
                ULONG SystemModeImage : 1;
                ULONG ImageMappedToAllPids : 1;
                ULONG ExtendedInfoPresent : 1;
                ULONG MachineTypeMismatch : 1;
                ULONG ImageSignatureLevel : 4;
                ULONG ImageSignatureType : 3;
                ULONG ImagePartialMap : 1;
                ULONG Reserved : 12;
            };
        };
        PVOID  ImageBase;
        ULONG  ImageSelector;
        SIZE_T ImageSize;
        ULONG  ImageSectionNumber;
    } IMAGE_INFO, *PIMAGE_INFO;`

    const imageInfoEx = `typedef struct _IMAGE_INFO_EX {
                                SIZE_T              Size;
                                IMAGE_INFO          ImageInfo;
                                struct _FILE_OBJECT *FileObject;
    } IMAGE_INFO_EX, *PIMAGE_INFO_EX;`

    const exCallbackFunction = `NTSTATUS ExCallbackFunction(
                        [in]           PVOID CallbackContext,
                        [in, optional] PVOID Argument1,
                        [in, optional] PVOID Argument2
    )`

    const regProtectDriverEntry = `#define DRIVER_PREFIX "MyDriver: "
        #define DRIVER_DEVICE_NAME L"\\\\Device\\\\MyDriver"
        #define DRIVER_SYMBOLIC_LINK L"\\\\??\\\\MyDriver"
        #define REG_CALLBACK_ALTITUDE L"31102.0003"
    
        PVOID g_RegCookie;
    
        NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
        UNREFERENCED_PARAMETER(RegistryPath);
        NTSTATUS status = STATUS_SUCCESS;
    
        UNICODE_STRING deviceName = RTL_CONSTANT_STRING(DRIVER_DEVICE_NAME);
        UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(DRIVER_SYMBOLIC_LINK);
        UNICODE_STRING regAltitude = RTL_CONSTANT_STRING(REG_CALLBACK_ALTITUDE);
    
        // Creating device and symbolic link.
        status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
    
        if (!NT_SUCCESS(status)) {
            KdPrint((DRIVER_PREFIX "Failed to create device: (0x%08X)\\n", status));
            return status;
        }
    
        status = IoCreateSymbolicLink(&symbolicLink, &deviceName);
    
        if (!NT_SUCCESS(status)) {
            KdPrint((DRIVER_PREFIX "Failed to create symbolic link: (0x%08X)\\n", status));
            IoDeleteDevice(DeviceObject);
            return status;
        }
    
        // Registering the registry callback.
        status = CmRegisterCallbackEx(RegNotify, &regAltitude, DriverObject, nullptr, &g_RegContext, nullptr);
    
        if (!NT_SUCCESS(status)) {
            KdPrint((DRIVER_PREFIX "Failed to register registry callback: (0x%08X)\\n", status));
            IoDeleteSymbolicLink(&symbolicLink);
            IoDeleteDevice(DeviceObject);
            return status;
        }
    
        DriverObject->DriverUnload = MyUnload;
        return status;
    }`

    const regProtectMyUnload = `void MyUnload(PDRIVER_OBJECT DriverObject) {
        KdPrint((DRIVER_PREFIX "Unloading...\\n"));
        NTSTATUS status = CmUnRegisterCallback(g_RegContext);

        if (!NT_SUCCESS(status)) {
            KdPrint((DRIVER_PREFIX "Failed to unregister registry callbacks: (0x%08X)\\n", status));
        }

        UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(DRIVER_SYMBOLIC_LINK);
        IoDeleteSymbolicLink(&symbolicLink);
        IoDeleteDevice(DriverObject->DeviceObject);
    }`

    const cmCallbackGetKey = `NTSTATUS CmCallbackGetKeyObjectIDEx(
                            [in] PLARGE_INTEGER Cookie,
                            [in] PVOID Object,
                            [out, optional] PULONG_PTR ObjectID,
                            [out, optional] PCUNICODE_STRING *ObjectName,
                            [in] ULONG Flags
    );`

    const regNotify = `NTSTATUS RegNotify(PVOID context, PVOID Argument1, PVOID Argument2) {
        PCUNICODE_STRING regPath;
        UNREFERENCED_PARAMETER(context);
        NTSTATUS status = STATUS_SUCCESS;

        switch ((REG_NOTIFY_CLASS)(ULONG_PTR)Argument1) {
        case RegNtPreDeleteKey: {
            REG_DELETE_KEY_INFORMATION* info = static_cast<REG_DELETE_KEY_INFORMATION*>(Argument2);
    
            // To avoid BSOD.
            if (!info->Object)
            break;
    
            status = CmCallbackGetKeyObjectIDEx(&g_RegContext, info->Object, nullptr, &regPath, 0);
    
            if (!NT_SUCCESS(status))
            break;
    
            if (!regPath->Buffer || regPath->Length < 50)
            break;
    
            if (_wcsnicmp(LR"(SYSTEM\\CurrentControlSet\\Services\\MaliciousService)", regPath->Buffer, 50) == 0) {
                KdPrint((DRIVER_PREFIX "Protected the malicious service!\\n"));
                status = STATUS_ACCESS_DENIED;
            }

            CmCallbackReleaseKeyObjectIDEx(regPath);
            break;
        }
        }

        return status;
    }`

    return (
        <div className="bg-bgInsideDiv p-6 rounded-xl h-full">
            <BlogPrologue title="Lord Of The Ring0 - Part 4 | The call back home"
                          date="24.02.2023" projectLink="https://github.com/Idov31/Nidhogg" />
            <div className="pt-4">
                <article>
                    <SecondaryHeader text="Prologue"/>
                    <div className="drop-caps pt-4">
                        In the <StyledLink href="/posts/lord-of-the-ring0-p3" content="last blog post"
                                           textSize="text-md"/>, we learned some debugging concepts, understood what is
                        IOCTL how to handle it
                        and started to learn how to validate the data that we get from the user mode - data that cannot
                        be
                        trusted and a handling mistake can cause a blue screen of death.

                        <div className="pt-2">
                            In this blog post, I&apos;ll explain the different types of callbacks and we will write another
                            driver to protect registry keys.
                        </div>
                    </div>
                    <SecondaryHeader text="Kernel Callbacks"/>
                    <div className="pt-4">
                        We started to talk about this subject in the 2nd part, so if you haven&apos;t read it yet read it
                        <StyledLink href="https://idov31.github.io/2022/08/04/lord-of-the-ring0-p2.html"
                                    content=" here"
                                    textSize="text-md"/> and come back as this blog is based on the knowledge you have
                        learned in the previous ones.

                        <div className="pt-2">
                            For starters, let&apos;s see what type of callbacks we&apos;re going to learn about today:

                            <BulletList items={[
                                {
                                    content: "Pre / Post operations (can be registered with ObRegisterCallbacks and " +
                                        "talked about it in the 2nd part)."
                                },
                                {
                                    content: "PsSet*NotifyRoutine."
                                },
                                {
                                    content: "CmRegisterCallbackEx."
                                }
                            ]}/>
                        </div>

                        Each of the mentioned callbacks has its purpose and difference and the most important thing to
                        know is to get the right tool for the job, so for each type, I will also give an example of how
                        it can be used in different scenarios.
                    </div>
                    <ThirdHeader text="ObRegisterCallbacks"/>
                    <div className="pt-4">
                        <StyledLink
                            href="https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obregistercallbacks"
                            content="ObRegisterCallbacks"
                            textSize="text-md"/> is a function that allows you to register a callback of your
                        choice for certain events (process, thread, and much more) before or after they&apos;re happening.
                        To register a callback you need to give the following structure:

                        <Code text={obCallbackRegistration}/>

                        <div className="pt-2">
                            <InlineCode text="Version"/> <b>MUST</b> be <InlineCode text="OB_FLT_REGISTRATION_VERSION"/>
                            .
                            <div className="pt-2">
                                <InlineCode text=" OperationRegistrationCount"/> is the number of registered callbacks.
                            </div>
                            <div className="pt-2">
                                <InlineCode text=" Altitude"/> is a unique identifier in form of a string with this
                                pattern
                                <InlineCode text=' #define OB_CALLBACKS_ALTITUDE L"XXXXX.XXXX"'/> where
                                <InlineCode text=" X"/> is a number.
                            </div>
                            <div className="pt-2">
                                It is mandatory to define one so the OS will be able to identify your driver and
                                determine
                                the <StyledLink
                                href="https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/load-order-groups-and-altitudes-for-minifilter-drivers"
                                content=" load order"
                                textSize="text-md"/> if you don&apos;t define it or if the
                                <InlineCode text=" Altitude"/> isn&apos;t unique the registration will fail.

                                <InlineCode text=" RegistrationContext"/> is the handle that will be used later on to
                                Unregister the callbacks.
                            </div>
                            <div className="pt-2">
                                Finally, <InlineCode text="OperationRegistration"/> is an array that contains all of
                                your
                                registered callbacks. <InlineCode text="OperationRegistration"/> and every callback have
                                this structure:
                            </div>
                        </div>

                        <Code text={obOperationRegistration}/>

                        <div className="pt-2">
                            <InlineCode text="ObjectType"/> is the type of operation that you want to register to.
                            Some of the most common types are <InlineCode text="*PsProcessType"/> and
                            <InlineCode text=" *PsThreadType"/>. It is worth mentioning that although you can enable
                            more types (like <InlineCode text="IoFileObjectType"/>) this will trigger PatchGuard and
                            cause your computer to BSOD, so unless PatchGuard is disabled it is highly not recommended
                            to enable more types. If you still want to enable more types, you can do so by using this
                            like so:
                        </div>

                        <Code text={obObjectType}/>
                        <div className="pt-2">
                            <InlineCode text="Operations"/> are the kind of operations that you are interested in,
                            it can be <InlineCode text="OB_OPERATION_HANDLE_CREATE"/> and/or
                            <InlineCode text=" OB_OPERATION_HANDLE_DUPLICATE"/> for a handle creation or duplication.
                            <div className="pt-2">
                                <InlineCode text=" PreOperation"/> is an operation that will be called before the handle
                                is
                                opened and <InlineCode text="PostOperation"/> will be called after it is opened.
                                In both cases, you are getting important information through
                                <InlineCode text=" OB_PRE_OPERATION_INFORMATION"/> or
                                <InlineCode text=" OB_POST_OPERATION_INFORMATION"/> such as a handle to the object,
                                the type of the object the return status, and what type of operation
                                (<InlineCode text=" OB_OPERATION_HANDLE_CREATE"/> or
                                <InlineCode text=" OB_OPERATION_HANDLE_DUPLICATE"/>) occurred. Both of them must
                                <b>ALWAYS</b> return <InlineCode text="OB_PREOP_SUCCESS"/>, if you want to change the
                                return status, you can change the <InlineCode text="ReturnStatus"/> that you got from
                                the
                                operation information, but do not return anything else.
                            </div>
                            <div className="pt-2">

                                After you registered this kind of callback, you can remove certain permissions from the
                                handle (for example: If you don&apos;t want to allow a process to be closed, you can just
                                remove
                                the <InlineCode text="PROCESS_TERMINATE"/> permission as we did in part 2 of the series)
                                or
                                manipulate the object itself (if it is a process, you can change the <StyledLink
                                href="https://www.vergiliusproject.com/kernels/x64/Windows%2011/22H2%20(2022%20Update)/_EPROCESS"
                                content="EPROCESS"
                                textSize="text-md"/> structure).
                            </div>

                            As you can see, these kinds of operations are very useful for both rootkits and AVs/EDRs to
                            protect their user mode component. Usually, if you have a user mode part you will want to
                            use some of these callbacks to make sure your process/thread is protected properly and
                            cannot be killed easily.
                        </div>
                    </div>
                    <ThirdHeader text="PsSet*NotifyRoutine"/>
                    <div className="pt-4">
                        Unlike <InlineCode text="ObRegisterCallbacks"/> PsSet notifies routines are not responsible for
                        a handle opening or duplicating operation but for monitoring creation/killing and loading
                        operations, while the most notorious ones are
                        <InlineCode text=" PsSetCreateProcessNotifyRoutine"/>,
                        <InlineCode text=" PsSetCreateThreadNotifyRoutine"/> and
                        <InlineCode text=" PsSetLoadImageNotifyRoutine"/> all of them are heavily used by AVs/EDRs to
                        monitor for certain process/thread creations and DLL loading. Let&apos;s break it down, and talk
                        about each function separately and what you can do with it.

                        <div className="pt-2">
                            <InlineCode text=" PsSetCreateProcessNotifyRoutine"/> receives a function of type
                            <InlineCode text=" PCREATE_PROCESS_NOTIFY_ROUTINE"/> which looks like so:
                            <Code text={createProcessNotifyRoutine}/>

                            <div className="pt-2">
                                <InlineCode text="ParentId"/> is the PID of the process that attempts to create or kill
                                the target process.
                            </div>
                            <div>
                                <InlineCode text="ProcessId"/> is the PID of the target process.
                            </div>
                            <div>
                                <InlineCode text="Create"/> indicates whether it is a create or kill operation.
                            </div>

                            The most common example of using this kind of routine is to watch certain processes and if
                            there
                            is an attempt to create a forbidden process (e.g. create a cmd directly under Winlogon), you
                            can kill it. Another example can be of creating a &quot;watchdog&quot; for a certain process and if
                            it is killed by an unauthorized process, restart it.
                        </div>

                        <div className="pt-2">
                            <InlineCode text="PsSetCreateThreadNotifyRoutine"/> receives a function of type
                            <InlineCode text=" PCREATE_THREAD_NOTIFY_ROUTINE"/> which looks like so:
                            <Code text={createThreadNotifyRoutine}/>

                            <div className="pt-2">
                                <p><InlineCode text="ProcessId"/> is the PID of the process.</p>
                                <p><InlineCode text="ThreadId"/> is the TID of the target thread.</p>
                                <p><InlineCode text="Create"/> indicates whether it is a create or kill operation.</p>
                            </div>

                            A simple example of using this kind of routine is if an EDR injected its library into a
                            process, make sure that the library&apos;s thread is getting killed.
                        </div>

                        <div className="pt-2">
                            <InlineCode text="PsSetLoadImageNotifyRoutine"/> receives a function of type
                            <InlineCode text=" PLOAD_IMAGE_NOTIFY_ROUTINE"/> which looks like so:
                            <Code text={loadImageNotifyRoutine}/>

                            <div className="pt-2">
                                <p><InlineCode text="FullImageName"/> is the name of the loaded image (a note here: it
                                    is not only DLLs and can be
                                    also EXE for example).</p>
                                <p><InlineCode text="ProcessId"/> is the PID of the target process.</p>
                                <p><InlineCode text="ImageInfo"/> is the most interesting part and contains a struct of
                                    type <InlineCode text="IMAGE_INFO"/>:</p>
                            </div>
                            <Code text={imageInfo}/>

                            <div className="pt-2">
                                The most important properties in my opinion are <InlineCode text="ImageBase"/> and
                                <InlineCode text=" ImageSize"/>, using these you can inspect and analyze the image
                                pretty
                                efficiently.
                                A simple example is if an attacker injects a DLL into LSASS, an EDR can inspect the
                                image and
                                unload it if it finds it malicious.
                                If the <InlineCode text="ExtendedInfoPresent"/> option is available, it means that this
                                struct is of type
                                <InlineCode text=" IMAGE_INFO_EX"/>:
                                <Code text={imageInfoEx}/>
                            </div>
                            <div className="pt-2">
                                As you can see, here you also get the <InlineCode text="FILE_OBJECT"/> which is a handle
                                for the file that is
                                backed on the disk. With that information, you can also check for reflective DLL
                                injection
                                (a
                                loaded DLL without any file backed on the disk) and it opens a door for you to monitor
                                for
                                more
                                injection methods that don&apos;t have a file on the disk.
                            </div>
                            <div className="pt-2">
                                These kinds of functions are usually used more for EDRs and AVs rather than rootkits,
                                because as
                                you can see it provides insights that are more useful for monitoring rather than doing
                                malicious
                                operations but that doesn&apos;t mean it doesn&apos;t have a use at all. For example, a rootkit
                                can use the <InlineCode text="PsSetLoadImageNotifyRoutine"/> to make sure that no
                                AV/EDR agent is injected into it.
                            </div>
                        </div>
                    </div>
                    <ThirdHeader text="CmRegisterCallbackEx"/>

                    <div className="pt-4">
                        <StyledLink
                            href="https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-cmregistercallbackex"
                            content="CmRegisterCallbackEx"
                            textSize="text-md"/> is responsible to register a registry callback that can monitor and
                        interfere with various registry operations such as registry key creation, deletion, querying and
                        more. Like the <InlineCode text="ObRegisterCallbacks"/> functions, it receives a unique altitude
                        and the callback function. Let&apos;s focus on the Registry callback function:

                        <Code text={exCallbackFunction}/>

                        <div className="pt-2">
                            <p><InlineCode text="CallbackContext"/> is the context that was passed on the function
                                registration with <InlineCode text="CmRegisterCallbackEx"/>.</p>
                            <p><InlineCode text="Argument1"/> is a variable that contains the information of what
                                operation was made (e.g. deletion, creation, setting value) and whether it is a post-
                                operation or pre-operation.
                            </p>
                            <p><InlineCode text="Argument2"/> is the information itself that is delivered and its type
                                matches the class that was specified in <InlineCode text="Argument1"/>.</p>
                        </div>
                        <div className="pt-2">
                            Using this callback, a rootkit can do many operations, from blocking a change to a specific
                            registry key, denying setting a specific value or hiding registry keys and values.
                        </div>
                        <div className="pt-2">
                            An example is a rootkit that saves its configuration in the registry and then hides it using
                            this callback. To give another practical example, we will create now another driver - a
                            driver
                            that can protect registry keys from deletion.
                        </div>
                    </div>
                    <SecondaryHeader text="Registry Protector"/>
                    <div className="pt-4">
                        First, let&apos;s start with the <InlineCode text="DriverEntry"/>:
                        <Code text={regProtectDriverEntry}/>

                        <div className="pt-2">
                            We added to the standard <InlineCode text="DriverEntry"/> initializations
                            (Creating DeviceObject and symbolic link) <InlineCode text="CmRegisterCallbackEx"/> to
                            register our <InlineCode text="RegNotify"/> callback. Note that we saved the
                            <InlineCode text=" g_RegContext"/> as a global variable, as it will be used soon in the
                            <InlineCode text=" MyUnload"/> function to unregister the driver when the
                            <InlineCode text=" DriverUnload"/> is called.
                        </div>

                        <Code text={regProtectMyUnload}/>

                        <div className="pt-2">
                            In <InlineCode text="MyUnload"/>, we didn&apos;t just unload the driver but also made sure to
                            unregister our callback using the <InlineCode text="g_RegContext"/> from before.

                            <Code text={regNotify}/>
                        </div>
                        <div className="pt-2">
                            Let&apos;s break down what we&apos;ve done here.
                            First, we checked what is the type of operation and chose to respond only for
                            <InlineCode text=" RegNtPreDeleteKey"/>. When we know that <InlineCode text="Argument2 "/>
                            contains information of type <StyledLink
                            href="https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_reg_delete_key_information"
                            content="REG_DELETE_KEY_INFORMATION"
                            textSize="text-md"/> we can cast to it.
                        </div>
                        <div className="pt-2">
                            After the cast, we can use the <InlineCode text="Object"/> parameter to access the registry
                            key itself to get the key&apos;s path. To do that, we can use
                            <InlineCode text=" CmCallbackGetKeyObjectIDEx"/>:
                            <Code text={cmCallbackGetKey}/>
                        </div>

                        <div className="pt-2">
                            <p><InlineCode text="Cookie"/> is our global <InlineCode text="g_RegContext"/> variable.</p>
                            <p><InlineCode text="Object"/> is the registry key object.</p>
                            <p><InlineCode text="ObjectID"/> is a unique registry identifier for our needs it can be
                                null.</p>
                            <div><InlineCode text="*ObjectName"/> is the output registry key path, make sure it is in
                                the <StyledLink
                                    href="https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/registry-key-object-routines"
                                    content="kernel format"
                                    textSize="text-md"/>.
                            </div>
                            <p><InlineCode text="Flags"/> must be 0.</p>
                        </div>
                        <div className="pt-2">
                            When you got the <InlineCode text="ObjectName"/> it is just a matter of comparing it and the
                            key that you want to protect and if it matches you can change the status to
                            <InlineCode text=" STATUS_ACCESS_DENIED"/> to block the operation.
                        </div>
                        <div className="pt-2">
                            You can see a full implementation of the different registry operations handling
                            in <StyledLink
                            href="https://github.com/Idov31/Nidhogg/blob/master/Nidhogg/RegistryUtils.cpp"
                            content="Nidhogg's Registry Utils"
                            textSize="text-md"/>.
                        </div>
                    </div>
                    <SecondaryHeader text="Conclusion"/>
                    <div className="pt-4">
                        In this blog, we learned about the different types of kernel callbacks and created our registry
                        protector driver.

                        <div className="pt-2">
                            In the next blog, we will learn two common hooking methods (IRP Hooking and SSDT Hooking)
                            and two different injection techniques from the kernel to the user mode for both shellcode
                            and DLL (APC and CreateThread) with code snippets and examples from Nidhogg.
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