"use client";

import SecondaryHeader, {BlogPrologue, BulletList, Code, InlineCode} from "@/components/BlogComponents";
import React from "react";
import StyledLink from "@/components/StyledLink";

export default function LordOfTheRing0P2() {
    const myDeviceObject = `NTSTATUS MyDeviceControl(
    [in] PDEVICE_OBJECT DeviceObject,
    [in] PIRP Irp
    );`;

    const obRegisterCallbacks = `NTSTATUS ObRegisterCallbacks(
    [in] POB_CALLBACK_REGISTRATION CallbackRegistration,
    [out] PVOID *RegistrationHandle
    );

    typedef struct _OB_CALLBACK_REGISTRATION {
    USHORT                    Version;
    USHORT                    OperationRegistrationCount;
    UNICODE_STRING            Altitude;
    PVOID                     RegistrationContext;
    OB_OPERATION_REGISTRATION *OperationRegistration;
} OB_CALLBACK_REGISTRATION, *POB_CALLBACK_REGISTRATION;

    typedef struct _OB_OPERATION_REGISTRATION {
    POBJECT_TYPE * ObjectType;
    OB_OPERATION                Operations;
    POB_PRE_OPERATION_CALLBACK  PreOperation;
    POB_POST_OPERATION_CALLBACK PostOperation;
} OB_OPERATION_REGISTRATION, *POB_OPERATION_REGISTRATION;`;

    const prePostOperationCallback = `OB_PREOP_CALLBACK_STATUS PobPreOperationCallback(
    [in] PVOID RegistrationContext,
    [in] POB_PRE_OPERATION_INFORMATION OperationInformation
    )

    void PobPostOperationCallback(
    [in] PVOID RegistrationContext,
    [in] POB_POST_OPERATION_INFORMATION OperationInformation
    )`;

    const protectorDriverEntry = `#include <ntddk.h>
    // Definitions
    #define IOCTL_PROTECT_PID CTL_CODE(0x8000, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
    #define PROCESS_TERMINATE 1

    // Prototypes
    DRIVER_UNLOAD ProtectorUnload;
    DRIVER_DISPATCH ProtectorCreateClose, ProtectorDeviceControl;

    OB_PREOP_CALLBACK_STATUS PreOpenProcessOperation(PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION Info)

    // Globals
    PVOID regHandle;
    ULONG protectedPid;

    NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING) {
    NTSTATUS status = STATUS_SUCCESS;
    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\\\Device\\\\Protector")
    UNICODE_STRING symName = RTL_CONSTANT_STRING(L"\\\\??\\\\Protector")
    PDEVICE_OBJECT DeviceObject = nullptr;

    OB_OPERATION_REGISTRATION operations[] = {
{
    PsProcessType,
    OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
    PreOpenProcessOperation, nullptr
}
}

    OB_CALLBACK_REGISTRATION reg = {
    OB_FLT_REGISTRATION_VERSION,
    1,
    RTL_CONSTANT_STRING(L"12345.6879"),
    nullptr,
    operations
}

    ...`;

    const protectorDriverEntry2 = `...

    status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, FALSE,
    &DeviceObject);

    if (!NT_SUCCESS(status)) {
        KdPrint((DRIVER_PREFIX "failed to create device object (status=%08X)\\n", status));
        return status;
    }

    status = IoCreateSymbolicLink(&symName, &deviceName);

    if (!NT_SUCCESS(status)) {
        KdPrint((DRIVER_PREFIX "failed to create symbolic link (status=%08X)\\n", status));
        IoDeleteDevice(DeviceObject);
        return status;
    }

    status = ObRegisterCallbacks(&reg, &regHandle);

    if (!NT_SUCCESS(status)) {
        KdPrint((DRIVER_PREFIX "failed to register the callback (status=%08X)\\n", status));
        IoDeleteSymbolicLink(&symName);
        IoDeleteDevice(DeviceObject);
        return status;
    }

    DriverObject->DriverUnload = ProtectorUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverObject->MajorFunction[IRP_MJ_CLOSE] =
    ProtectorCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ProtectorDeviceControl;

    KdPrint(("DriverEntry completed successfully\\n"));
    return status;
    }
    
void ProtectorUnload(PDRIVER_OBJECT DriverObject) {
    ObUnRegisterCallbacks(regHandle);

    UNICODE_STRING symName = RTL_CONSTANT_STRING(L"\\\\??\\\\Protector");
    IoDeleteSymbolicLink(&symName);
    IoDeleteDevice(DriverObject->DeviceObject);
}`;

    const protectorCreateClose = `NTSTATUS ProtectorCreateClose(PDEVICE_OBJECT, PIRP Irp) {
        Irp->IoStatus.Status = STATUS_SUCCESS;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }`;

    const protectorDeviceControl = `NTSTATUS ProtectorDeviceControl(PDEVICE_OBJECT, PIRP Irp) {
        NTSTATUS status = STATUS_SUCCESS;
        auto stack = IoGetCurrentIrpStackLocation(Irp);

        switch (stack->Parameters.DeviceIoControl.IoControlCode) {
        case IOCTL_PROTECT_PID:
        {
            auto size = stack->Parameters.DeviceIoControl.InputBufferLength;
    
            if (size % sizeof(ULONG) != 0) {
            status = STATUS_INVALID_BUFFER_SIZE;
            break;
        }
    
            auto data = (ULONG*)Irp->AssociatedIrp.SystemBuffer;
            protectedPid = *data;
            break;
        }
            default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
        }

        Irp->IoStatus.Status = status;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return status;
    }`;

    const preOpenProcessOperation = `OB_PREOP_CALLBACK_STATUS PreOpenProcessOperation(PVOID, POB_PRE_OPERATION_INFORMATION Info) {
        if (Info->KernelHandle)
            return OB_PREOP_SUCCESS;

        auto process = (PEPROCESS)Info->Object;
        auto pid = HandleToULong(PsGetProcessId(process));

        // Protecting our pid and removing PROCESS_TERMINATE.
        if (pid == protectedPid) {
            Info->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
        }

        return OB_PREOP_SUCCESS;
    }`;

    const userModePart = `#include <iostream>
#include <Windows.h>
#define IOCTL_PROTECT_PID CTL_CODE(0x8000, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

int main(int argc, const char* argv[]) {
    DWORD bytes;

    if (argc != 2) {
        std::cout << "Usage: " << argv[0] << " <pid>" << std::endl;
        return 1;
    }

    DWORD pid = atoi(argv[1]);
    HANDLE device = CreateFile(L"\\\\\\\\.\\\\Protector", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);

    if (device == INVALID_HANDLE_VALUE) {
        std::cout << "Failed to open device" << std::endl;
        return 1;
    }

    BOOL success = DeviceIoControl(device, IOCTL_PROTECT_PID, &pid, sizeof(pid), nullptr, 0, &bytes, nullptr);
    CloseHandle(device);

    if (!success) {
        std::cout << "Failed in DeviceIoControl: " << GetLastError() << std::endl;
        return 1;
    }
    
    std::cout << "Protected process with pid: " << pid << std::endl;
    return 0;
}`;

    return (
        <div className="bg-bgInsideDiv p-6 rounded-xl h-full">
            <BlogPrologue title="Lord Of The Ring0 - Part 2 | A tale of routines, IOCTLs and IRPs"
                          date="04.08.2022" projectLink="https://github.com/Idov31/Nidhogg"/>
            <div className="pt-4">
                <article>
                    <SecondaryHeader text="Prologue"/>
                    <div className="pt-4">
                        In the <StyledLink href="/posts/lord-of-the-ring0-p1"
                                           content="last blog post" textSize="text-md"/>, we had
                        an introduction to kernel development and what are the difficulties when trying to load a driver
                        and how to bypass it. In this blog, I will write more about callbacks, how to start writing a
                        rootkit and the difficulties I encountered during my development of Nidhogg.

                        <div className="pt-2">
                            As I promised to bring both defensive and offensive points of view, we will create a driver
                            that can be used for both blue and red teams - A process protector driver.
                        </div>
                        <div className="pt-2">
                            <i>P.S: The name Nidhogg was chosen after the nordic dragon that lies underneath Yggdrasil
                                :).</i>
                        </div>
                    </div>
                    <SecondaryHeader text="Talking with the user mode 101"/>
                    <div className="pt-4">
                        A driver should be (most of the time) controllable from the user mode by some process, an
                        example would be Sysmon - When you change the configuration, turn it off or on it tells its
                        kernel part to stop performing certain operations, works by an updated policy or just shut down
                        it when you decide to unload Sysmon.

                        <div className="pt-2">
                            As kernel drivers, we have two ways to communicate with the
                            user mode: Via <InlineCode text="DIRECT_IO"/> or <InlineCode text="IOCTLs"/>. The advantage
                            of
                            <InlineCode text=" DIRECT_IO"/> is that it is more simple to use and you have more control
                            and
                            the advantage of using <InlineCode text="IOCTLs"/> is that it is safer and developer
                            friendly.
                            In this blog series, we will use the <InlineCode text="IOCTLs"/> approach.
                        </div>

                        <div className="pt-2">
                            To understand what is an <InlineCode text="IOCTL"/> better, let&apos;s look at an IOCTL
                            structure:
                        </div>
                        <InlineCode text="#define MY_IOCTL CTL_CODE(DeviceType, FunctionNumber, Method, Access)"/>
                        <div className="pt-2">
                            The device type indicates what is the type of the device (different types of hardware and
                            software drivers), it doesn&apos;t matter much for software drivers will be the number but the
                            convention is to use 0x8000 for 3rd software drivers like ours.
                        </div>
                        <div className="pt-2">
                            The second parameter indicates the function &quot;index&quot; in our driver, it could be any number
                            but the convention suggests starting from <InlineCode text="0x800"/>.
                        </div>
                        <div className="pt-2">
                            The method parameter indicates how the input and output should be handled by the driver, it
                            could be either <InlineCode text="METHOD_BUFFERED"/> or
                            <InlineCode text=" METHOD_IN_DIRECT"/> or <InlineCode text="METHOD_OUT_DIRECT"/> or
                            <InlineCode text=" METHOD_NEITHER"/>.
                        </div>

                        <div className="pt-2">
                            The last parameter indicates if the driver accepts the operation
                            (<InlineCode text=" FILE_WRITE_ACCESS"/>) or the driver operates
                            (<InlineCode text=" FILE_READ_ACCESS"/>) or the driver accepts and performs the operation
                            (<InlineCode text=" FILE_ANY_ACCESS"/>).
                        </div>

                        <div className="pt-2">
                            To use IOCTLs, on the driver&apos;s initialization you will need to set a function that will
                            parse an <InlineCode text="IRP"/> and knows how to handle the <InlineCode text="IOCTL"/>,
                            such a function is defined as followed:
                        </div>
                        <Code text={myDeviceObject}/>

                        <div className="pt-2">
                            <InlineCode text="IRP"/> in a nutshell is a structure that represents an I/O request packet.
                            You can read more about it in <StyledLink
                            href="https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_irp"
                            content="MSDN" textSize="text-md"/>.
                        </div>

                        <div className="pt-2">
                            When communicating with the user mode we need to define two more things: The device object
                            and
                            the symbolic link. <StyledLink
                            href="https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_device_object"
                            content="The device object" textSize="text-md"/> is the object that handles the I/O requests
                            and allows us as a user-mode program to communicate with the kernel driver. The symbolic
                            link creates a linkage in the <InlineCode text="GLOBAL??"/> directory so the
                            <InlineCode text=" DeviceObject"/> will be accessible from the user mode and usually looks
                            like <InlineCode text="\\??\DriverName"/>.
                        </div>
                    </div>
                    <SecondaryHeader text="Callback Routines"/>
                    <div className="pt-4">
                        To understand how to use callback routines let&apos;s understand <b>WHAT</b> are they. The callback
                        routine is a feature that allows kernel drivers to register for certain events, an example would
                        be process operation (such as: getting a handle to process) and affect their result. When a
                        kernel driver registers for an operation, it notifies &quot;I&apos;m interested in the certain event and
                        would like to be notified whenever this event occurs&quot; and then for each time this event occurs
                        the driver is get notified and a function is executed.

                        <div className="pt-2">
                            One of the most notable ways to register for an operation is with the
                            <InlineCode text=" ObRegisterCallbacks"/> function:
                        </div>
                        <Code text={obRegisterCallbacks}/>

                        <div className="pt-2">
                            Using this callback we can register for two types of
                            <InlineCode text=" OperationRegistration"/>: <InlineCode text="ObjectPreCallback "/>
                            and <InlineCode text="ObjectPostCallback"/>. The pre-callback happens before the operation
                            is executed and the post-operation happens after the operation is executed and before the
                            user gets back the output.
                        </div>

                        <div className="pt-2">
                            Using <InlineCode text="ObRegisterCallbacks"/> you can register for this
                            <InlineCode text=" ObjectTypes"/> of operations (You can see the full list defined in
                            <InlineCode text=" WDM.h"/>):
                        </div>

                        <BulletList items={[
                            {
                                content: "PsProcessType"
                            },
                            {
                                content: "PsThreadType"
                            },
                            {
                                content: "ExDesktopObjectType"
                            },
                            {
                                content: "IoFileObjectType"
                            },
                            {
                                content: "CmKeyObjectType"
                            },
                            {
                                content: "ExEventObjectType"
                            },
                            {
                                content: "SeTokenObjectType"
                            },
                            {
                                content: "..."
                            },
                        ]}/>

                        <div className="pt-2">
                            To use this function, you will need to create a function with a unique signature as follows
                            (depending on your needs and if you are using <InlineCode text="PreOperation"/> or
                            <InlineCode text=" PostOperation"/>):
                        </div>
                        <Code text={prePostOperationCallback}/>

                        <div className="pt-2">
                            Now that we understand better what callbacks are we can write our first driver - A kernel
                            driver that protects a process.
                        </div>
                    </div>
                    <SecondaryHeader text="Let's build - Process Protector"/>
                    <div className="pt-4">
                        To build a process protector we need to first understand how will it work.
                        What we want is basic protection against any process that attempts to kill our process, the
                        protected process could be our malicious program or our precious Sysmon agent. To perform the
                        killing of a process the process that performs the killing will need a handle with the
                        <InlineCode text="PROCESS_TERMINATE"/> permissions, and before we said that we could register
                        for
                        certain events like a request for the handle to process. So as a driver, you could remove
                        permissions from a handle and return a handle without specific permission which is in our case
                        the <InlineCode text="PROCESS_TERMINATE"/> permission.

                        <div className="pt-2">
                            To start with the development we will need a DriverEntry function:
                        </div>
                        <Code text={protectorDriverEntry}/>

                        <div className="pt-2">
                            Before we continue let&apos;s explain what&apos;s going on, we defined a deviceName with our driver
                            name (Protector) and a symbolic link with the same name (the symName parameter). We also
                            defined an array of operations that we want to register for - In our case it is just the
                            <InlineCode text="PsProcessType"/> for each handle creation or handle duplication.
                        </div>
                        <div className="pt-2">
                            We used this array to finish the registration definition - the number 1 stands for only 1
                            operation to be registered, and the <InlineCode text="12345.6879"/> defines the altitude.
                            An altitude is a unique double number (but using a <InlineCode text="UNICODE_STRING"/> to
                            represent it) that is used to identify registration and relate it to a certain driver.
                        </div>
                        <div className="pt-2">
                            As you probably noticed, the DriverEntry is &quot;missing&quot; the <InlineCode text="RegistryPath "/>
                            parameter, to not write <InlineCode text="UNREFERENCED_PARAMETER(RegistryPath)"/> we can
                            just not write it and it will be unreferenced.
                        </div>
                        <div className="pt-2">
                            Now, let&apos;s do the actual registration and finish the <InlineCode text="DriverEntry "/>
                            function:
                        </div>
                        <Code text={protectorDriverEntry2}/>

                        <div className="pt-2">
                            Using the functions <InlineCode text="IoCreateDevice"/> and <InlineCode
                            text="IoCreateSymbolicLink"/> we created a device object and a symbolic link. After we know
                            our driver can be reached from the user mode we registered our callback with <InlineCode
                            text="ObRegisterCallbacks"/> and defined important major functions such as
                            <InlineCode text=" ProtectorCreateClose"/> (will explain it soon) and <InlineCode
                            text="ProtectorDeviceControl"/> to handle the IOCTL.
                        </div>
                        <div className="pt-2">
                            The <InlineCode text="ProtectorUnload"/> function is very simple and just does the cleanup
                            like we did if the status wasn&apos;t successful: The next thing on the list is to implement
                            the <InlineCode text="ProtectorCreateClose"/> function.
                            The function is responsible on complete the IRP, since in this driver we don&apos;t have multiple
                            device objects and we are not doing much with it we can handle the completion of the
                            relevant IRP in our <InlineCode text="DeviceControl"/> function and for any other IRP just
                            close it always with a successful status.
                        </div>
                        <Code text={protectorCreateClose}/>

                        <div className="pt-2">
                            The device control is also fairly simple as we have only one IOCTL to handle:
                        </div>
                        <Code text={protectorDeviceControl}/>

                        <div className="pt-2">
                            As you noticed, to see the IOCTL, get the input and for more operations in the future, we
                            need to use the IRP&apos;s stack. I won&apos;t go over its entire structure but you can view it in
                            <StyledLink
                                href="https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_io_stack_location"
                                content="MSDN" textSize="text-md"/>. To make it clearer, when using the
                            <InlineCode text="METHOD_BUFFERED"/> option the input and output buffers are delivered via
                            the <InlineCode text="SystemBuffer"/> that is located within the IRP&apos;s stack.
                        </div>

                        <div className="pt-2">
                            After we got the stack and verified the IOCTL, we need to check our input because wrong
                            input
                            handling can cause a BSOD. When the input verification is completed all we have to do is
                            just
                            change the <InlineCode text="protectedPid"/> to the wanted PID.
                        </div>

                        <div className="pt-2">
                            With the <InlineCode text="DeviceControl"/> and the <InlineCode text="CreateClose "/>
                            functions, we can create the last function in the kernel driver - The
                            <InlineCode text=" PreOpenProcessOperation"/>.
                        </div>
                        <Code text={preOpenProcessOperation}/>

                        <div className="pt-2">
                            Very simple isn&apos;t it? Just logic and the opposite value of the
                            <InlineCode text=" PROCESS_TERMINATE"/> and we are done.
                        </div>
                        <div className="pt-2">
                            Now, we have left only one thing to make sure and it is to allow our driver to register for
                            operation registration, <b>it can be done within the project settings in Visual Studio in
                            the
                            linker command line and just add <InlineCode text="/integritycheck"/> switch</b>.
                        </div>
                        <div className="pt-2">
                            After we finished with the kernel driver part let&apos;s go to the user-mode part.
                        </div>
                    </div>

                    <SecondaryHeader text="Protector's User Mode Part"/>
                    <div className="pt-4">
                        The user-mode part is even simple as we just need to create a handle for the device object and
                        send the wanted PID.

                        <Code text={userModePart}/>

                        <div className="pt-2">
                            Congratulations on writing your very first functional kernel driver!
                        </div>
                    </div>

                    <SecondaryHeader text="Bonus - Anti-dumping"/>
                    <div className="pt-4">
                        To prevent a process from being dumped all we have to do is just remove more permissions such as
                        <InlineCode text=" PROCESS_VM_READ"/>, <InlineCode text="PROCESS_DUP_HANDLE"/> and
                        <InlineCode text=" PROCESS_VM_OPERATION"/>. An example can be found in
                        <StyledLink href="https://github.com/Idov31/Nidhogg/blob/master/Nidhogg/ProcessUtils.cpp#L45"
                                    content=" Nidhogg's ProcessUtils file" textSize="text-md"/>.
                    </div>

                    <SecondaryHeader text="Conclusion"/>
                    <div className="pt-4">
                        In this blog, we got a better understanding of how to write a driver, how to communicate it and
                        how to use callbacks. In the next blog, we will dive more into this world and learn more new
                        things about kernel development.

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