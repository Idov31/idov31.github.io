"use client";

import React from "react";
import StyledLink from "@/components/StyledLink";
import SecondaryHeader, {
    BlogPrologue,
    BulletList,
    InlineCode,
    ThirdHeader,
} from "@/components/BlogComponents";
import BlogImageFigure from "@/components/BlogImageFigure";
import RoadmapTimeline from "@/components/RoadmapTimeline";

export default function HypervisorBasedDefense() {
    return (
        <div className="glass-card p-6 sm:p-8 lg:p-10 animate-fade-in prose-blog">
            <BlogPrologue
                title="Hypervisor Based Defense"
                date="14.03.2026"
                projectLink="https://github.com/Idov31/NovaHypervisor"
            />
            <div className="pt-4">
                <article>
                    <SecondaryHeader text="Table of Contents" />
                    <nav className="pt-4 pb-2">
                        <ul className="space-y-1">
                            <li><StyledLink href="#prologue" content="Prologue" textSize="text-md" /></li>
                            <li><StyledLink href="#why-virtualization" content="Why Virtualization" textSize="text-md" /></li>
                            <li>
                                <StyledLink href="#virtualization-crash-course" content="Virtualization Crash Course" textSize="text-md" />
                                <ul className="pl-6 mt-1 space-y-1">
                                    <li><StyledLink href="#types-of-hypervisors" content="Types of Hypervisors" textSize="text-md" /></li>
                                    <li><StyledLink href="#virtualization-platforms" content="Virtualization Platforms" textSize="text-md" /></li>
                                    <li>
                                        <StyledLink href="#basics-of-virtualization" content="Basics of Virtualization" textSize="text-md" />
                                        <ul className="pl-6 mt-1 space-y-1">
                                            <li><StyledLink href="#hypervisor-role-and-architecture" content="Hypervisor Role and Architecture" textSize="text-md" /></li>
                                            <li>
                                                <StyledLink href="#state-management" content="State Management" textSize="text-md" />
                                                <ul className="pl-6 mt-1 space-y-1">
                                                    <li><StyledLink href="#virtual-machine-control-structure-(vmcs)" content="Virtual Machine Control Structure (VMCS)" textSize="text-md" /></li>
                                                    <li><StyledLink href="#extended-page-table-(ept)" content="Extended Page Table (EPT)" textSize="text-md" /></li>
                                                    <li><StyledLink href="#page-table-entries-(pte)" content="Page Table Entries (PTE)" textSize="text-md" /></li>
                                                    <li><StyledLink href="#communication-between-hypervisor-and-guest" content="Communication Between Hypervisor and Guest" textSize="text-md" /></li>
                                                </ul>
                                            </li>
                                            <li><StyledLink href="#nested-virtualization" content="Nested Virtualization" textSize="text-md" /></li>
                                        </ul>
                                    </li>
                                </ul>
                            </li>
                            <li>
                                <StyledLink href="#why-do-we-even-need-hypervisor-based-defense?" content="Why Do We Even Need Hypervisor-Based Defense?" textSize="text-md" />
                                <ul className="pl-6 mt-1 space-y-1">
                                    <li>
                                        <StyledLink href="#what-is-hypervisor-based-defense?" content="What Is Hypervisor-Based Defense?" textSize="text-md" />
                                        <ul className="pl-6 mt-1 space-y-1">
                                            <li><StyledLink href="#virtualization-based-security-(vbs)" content="Virtualization-Based Security (VBS)" textSize="text-md" /></li>
                                            <li><StyledLink href="#hypervisor-enforced-code-integrity-(hvci)" content="Hypervisor-Enforced Code Integrity (HVCI)" textSize="text-md" /></li>
                                        </ul>
                                    </li>
                                </ul>
                            </li>
                            <li><StyledLink href="#motivation-behind-nova" content="Motivation Behind Nova" textSize="text-md" /></li>
                            <li>
                                <StyledLink href="#nova-architecture" content="Nova Architecture" textSize="text-md" />
                                <ul className="pl-6 mt-1 space-y-1">
                                    <li><StyledLink href="#ept-hooks" content="EPT Hooks" textSize="text-md" /></li>
                                    <li><StyledLink href="#hypervisor-vs-kernel-level-threats" content="Hypervisor vs Kernel Level Threats" textSize="text-md" /></li>
                                    <li><StyledLink href="#what-is-next?" content="What Is Next?" textSize="text-md" /></li>
                                </ul>
                            </li>
                            <li><StyledLink href="#epilogue" content="Epilogue" textSize="text-md" /></li>
                        </ul>
                    </nav>

                    <SecondaryHeader text="Prologue" />
                    <div className="drop-caps pt-4">
                        Hey there, it has been a &quot;little&quot; while since I published my
                        last post. After scrapping and rewriting multiple ideas, I decided to
                        write something a bit different from my previous posts.
                    </div>
                    <div className="pt-2">
                        This post contains technical information, but I also wanted to share
                        my thoughts after working on a hypervisor project for more than a
                        year. I will cover the motivation behind the project, what I learned
                        from building Nova, what I want it to become, and where I think
                        hypervisor-based defense is heading.
                    </div>
                    <div className="pt-2">
                        If you have not already, grab a cup of coffee and let&apos;s look at the
                        emerging world of hypervisor-based defense together.
                    </div>

                    <SecondaryHeader text="Why Virtualization" />
                    <div className="pt-4">
                        Before looking at how virtualization works, or why it matters for
                        defense, it is worth asking a simpler question: why do we even need
                        virtualization in the first place? What does it give us that we
                        cannot achieve without it, and why is it worth adding another layer
                        of complexity to the system?
                    </div>

                    <ThirdHeader text="Virtualization Crash Course" />
                    <div className="pt-4">
                        Virtualization is a set of technologies that allows the division of
                        physical computing resources into virtual machines. Historically, the
                        idea goes back to IBM&apos;s CP/CMS work in the 1960s.
                    </div>
                    <div className="pt-2">
                        At a high level, there are two main entities: the hypervisor and the
                        guest virtual machines. In hosted virtualization, the hypervisor runs
                        on top of a host operating system. In both cases, the hypervisor is
                        responsible for managing virtual machines and allocating resources to
                        them. The virtual machine itself is a software representation of a
                        physical computer that runs its own operating system and
                        applications.
                    </div>
                    <div className="pt-2">
                        In simple terms, virtualization allows us to run multiple operating
                        systems on a single physical machine, each inside its own isolated
                        environment. That isolation is useful not only for infrastructure and
                        cloud platforms, but also for security.
                    </div>

                    <ThirdHeader text="Types of Hypervisors" />
                    <div className="pt-4">
                        There are two main types of hypervisors:
                    </div>
                    <BulletList
                        items={[
                            {
                                content:
                                    'Type 1 hypervisors, also known as "bare-metal" hypervisors, run directly on the hardware. Examples include VMware ESXi, Microsoft Hyper-V, and Xen.',
                            },
                            {
                                content:
                                    'Type 2 hypervisors, also known as "hosted" hypervisors, run on top of a host operating system. Examples include Oracle VirtualBox and VMware Workstation.',
                            },
                        ]}
                    />
                    <div className="pt-2">
                        While Type 1 hypervisors are more commonly used for security purposes (as we will see later on in the VBS section), in this post, I focus mostly on the Type 2 model because that is the
                         environment I used while building and testing Nova.
                    </div>

                    <ThirdHeader text="Virtualization Platforms" />
                    <div className="pt-4">
                        There are several hardware virtualization technologies that provide
                        the foundation for modern hypervisors:
                    </div>
                    <BulletList
                        items={[
                            {
                                content:
                                    "Intel VT-x, Intel's hardware-assisted virtualization technology, introduced in 2005 and widely supported on modern Intel processors.",
                            },
                            {
                                content:
                                    "AMD-V, AMD's counterpart to VT-x, also introduced in 2005 and widely supported on modern AMD processors.",
                            },
                            {
                                content:
                                    "ARM virtualization extensions, which introduce EL2 (hypervisor mode) and stage-2 memory translation on ARM platforms.",
                            },
                        ]}
                    />
                    <div className="pt-2">
                        These technologies are the backbone of platforms such as VMware,
                        Hyper-V, and VirtualBox. Virtualization affects our lives not only
                        from a security perspective, through mechanisms such as sandboxing and
                        virtualization-based security, but also from an infrastructure
                        perspective, since it enables cloud providers such as AWS, Azure, and
                        Google Cloud to deliver virtualized resources at scale.
                    </div>

                    <SecondaryHeader text="Basics of Virtualization" />
                    <div className="pt-4">
                        This is not meant to be a comprehensive guide. It is a high-level
                        overview of the core concepts that are useful for understanding
                        hypervisor-based defense. If you want to go deeper, I highly
                        recommend Sina Karvandi&apos;s{" "}
                        <StyledLink
                            href="https://rayanfam.com/topics/hypervisor-from-scratch-part-1/"
                            content="Hypervisor From Scratch series"
                            textSize="text-md"
                        />
                        , along with the official vendor documentation for the platform you
                        care about.
                    </div>
                    <div className="pt-2">
                        For simplicity, I focus on Intel VT-x. The same general ideas carry
                        over to AMD-V and ARM, even though the implementation details differ.
                    </div>

                    <ThirdHeader text="Hypervisor Role and Architecture" />
                    <div className="pt-4">
                        If we break the hypervisor down to its essentials, it has two main
                        responsibilities:
                    </div>
                    <BulletList
                        items={[
                            {
                                content:
                                    "Managing the virtual machines' state and resources, such as CPU, memory, and I/O devices.",
                            },
                            {
                                content:
                                    "Providing an interface between the guests and the underlying physical hardware.",
                            },
                        ]}
                    />
                    <div className="pt-2">
                        That sounds simple on paper, but in practice it is a complex job
                        that requires careful handling of CPU state, memory translation, and
                        event interception.
                    </div>

                    <ThirdHeader text="State Management" />
                    <div className="pt-4">
                        State management is one of the hypervisor&apos;s critical jobs. It
                        involves tracking enough state to start, stop, resume, and switch
                        virtual machines cleanly and securely. Several structures are central
                        here, especially the <InlineCode text="VMCS" />, guest page tables,
                        and <InlineCode text="EPT" />.
                    </div>

                    <ThirdHeader text="Virtual Machine Control Structure (VMCS)" />
                    <div className="pt-4">
                        The Virtual Machine Control Structure, or{" "}
                        <InlineCode text="VMCS" />, is the data structure Intel uses to
                        describe guest state, host state, and the controls that define how
                        virtualization behaves. It tells the processor what state to restore
                        on VM entry, what state to save on VM exit, and which events should
                        transfer control back to the hypervisor.
                    </div>

                    <BlogImageFigure
                        src="/post-images/hypervisor-based-defense/vmcs_guest_host_states.jpg"
                        alt="Guest and host state areas inside VMCS"
                        caption="Source: Hypervisor From Scratch - Part 1"
                        sourceHref="https://rayanfam.com/topics/hypervisor-from-scratch-part-1/"
                    />

                    <div className="pt-2">
                        The guest and host state areas share many structural similarities.
                        They contain architectural state such as control registers, segment
                        registers, debug registers, and descriptor-table information. Some of
                        the fields that are especially relevant here are:
                    </div>
                    <BulletList
                        items={[
                            {
                                content:
                                    "CR3, which points to the root of the guest page tables and is central to virtual memory management.",
                            },
                            {
                                content:
                                    "GDTR and IDTR, which describe the Global Descriptor Table and Interrupt Descriptor Table.",
                            },
                            {
                                content:
                                    "CS and SS, which define the code and stack segments.",
                            },
                            {
                                content:
                                    "DR7, which controls hardware breakpoints and is relevant for debugging and monitoring.",
                            },
                        ]}
                    />

                    <BlogImageFigure
                        src="/post-images/hypervisor-based-defense/vmcs_control_fields.jpg"
                        alt="VMCS control fields"
                        caption="Source: Hypervisor From Scratch - Part 1"
                        sourceHref="https://rayanfam.com/topics/hypervisor-from-scratch-part-1/"
                    />

                    <div className="pt-2">
                        The control fields define which events cause VM exits. At a high
                        level, they are usually discussed in terms of pin-based controls,
                        primary processor-based controls, and secondary controls.
                    </div>
                    <div className="pt-2">
                        Examples include intercepting <InlineCode text="CPUID" />,
                        <InlineCode text="INVLPG" />, control-register access, and EPT
                        violations. These are the hooks that let a hypervisor observe or
                        enforce behavior in a guest.
                    </div>

                    <ThirdHeader text="Extended Page Table (EPT)" />
                    <div className="pt-4">
                        EPT is Intel&apos;s implementation of second-level address translation, or{" "}
                        <InlineCode text="SLAT" />. It gives the hypervisor its own layer of
                        control over guest memory and is one of the main reasons modern
                        hardware virtualization is practical from a performance standpoint.
                    </div>

                    <BlogImageFigure
                        src="/post-images/hypervisor-based-defense/ept.png"
                        alt="Extended Page Table hierarchy"
                        caption="Source: Hypervisor From Scratch - Part 4"
                        sourceHref="https://rayanfam.com/topics/hypervisor-from-scratch-part-4/"
                    />

                    <div className="pt-2">
                        Conceptually, the memory translation pipeline looks like this:
                    </div>
                    <BulletList
                        items={[
                            {
                                content:
                                    "Guest virtual addresses are translated to guest physical addresses through the guest page tables rooted at CR3.",
                            },
                            {
                                content:
                                    "Guest physical addresses are then translated to host physical addresses through EPT, rooted at the EPT pointer stored in the VMCS.",
                            },
                        ]}
                    />
                    <div className="pt-2">
                        That split is important. The guest still believes it owns its own
                        memory mappings, but the hypervisor gets a second, independent layer
                        of control over what physical memory is actually reachable and with
                        what permissions.
                    </div>

                    <ThirdHeader text="Page Table Entries (PTE)" />
                    <div className="pt-4">
                        Guest page tables are still worth discussing because they remain the
                        first stage in the translation pipeline. A page table entry maps a
                        guest virtual address to a guest physical address and carries
                        permissions such as read/write access, supervisor-only access,
                        caching behavior, and software-defined bits.
                    </div>

                    <BlogImageFigure
                        src="/post-images/hypervisor-based-defense/pte.png"
                        alt="Page table entry layout"
                        caption="Source: OSDev Wiki"
                        sourceHref="https://wiki.osdev.org/Paging"
                    />

                    <div className="pt-2">
                        The important point is not memorizing every bit, but understanding
                        that guest page tables and EPT serve different roles. One controls
                        the guest&apos;s view of memory; the other controls the hypervisor&apos;s
                        view of the guest.
                    </div>

                    <ThirdHeader text="Communication Between Hypervisor and Guest" />
                    <div className="pt-4">
                        Hypervisors and guests communicate in a few main ways. Two of the
                        most relevant are <InlineCode text="VMCALL" /> instructions and VM
                        exits.
                    </div>
                    <BulletList
                        items={[
                            {
                                content:
                                    "VMCALLs allow the guest to intentionally transfer control to the hypervisor, similar in spirit to a system call.",
                            },
                            {
                                content:
                                    "VM exits occur when configured events happen, such as CPUID execution, control-register access, I/O instructions, or EPT violations.",
                            },
                        ]}
                    />
                    <div className="pt-2">
                        When a VM exit occurs, the processor saves the relevant guest state
                        defined in the VMCS, restores the relevant host state, and records
                        the reason for the exit so the hypervisor can handle it correctly.
                    </div>

                    <ThirdHeader text="Nested Virtualization" />
                    <div className="pt-4">
                        Nested virtualization means running a hypervisor inside a virtual
                        machine that is itself managed by another hypervisor. This is useful
                        for research, testing, and development, but it also adds significant
                        complexity because multiple layers now participate in the same
                        virtualization flow.
                    </div>

                    <SecondaryHeader text="Why Do We Even Need Hypervisor-Based Defense?" />
                    <div className="pt-4">
                        Now that the groundwork is in place, we can talk about what
                        hypervisor-based defense actually is. In broad terms, it is a
                        security approach that uses virtualization primitives to enforce
                        protections from a higher privilege level than the guest kernel.
                    </div>

                    <ThirdHeader text="What Is Hypervisor-Based Defense?" />
                    <div className="pt-4">
                        Most major operating systems now expose some form of this idea:
                    </div>
                    <BulletList
                        items={[
                            {
                                content:
                                    "On Windows, it is most visible through Virtualization-Based Security (VBS).",
                            },
                            {
                                content:
                                    "On Android, it appears through the Android Virtualization Framework (AVF).",
                            },
                            {
                                content:
                                    "On Apple platforms, related ideas show up through secure execution environments and hardware-backed isolation mechanisms.",
                            },
                        ]}
                    />
                    <div className="pt-2">
                        The details differ, but the common theme is the same: move security
                        decisions into an isolated execution environment that a compromised
                        kernel cannot easily tamper with.
                    </div>

                    <ThirdHeader text="Virtualization-Based Security (VBS)" />
                    <div className="pt-4">
                        On Windows, VBS uses the Windows hypervisor to create an isolated
                        environment that becomes a higher-trust part of the operating system.
                        Microsoft uses that environment to host security-critical logic that
                        should remain protected even if the normal kernel is compromised.
                    </div>
                    <div className="pt-2">
                        At a high level, VBS is commonly discussed in three buckets:
                    </div>
                    <BulletList
                        items={[
                            {
                                content:
                                    "Memory-protection features such as Hypervisor-Enforced Code Integrity (HVCI).",
                            },
                            {
                                content:
                                    "Virtual Trust Levels (VTLs), mainly VTL0 for the normal world and VTL1 for the secure world.",
                            },
                            {
                                content:
                                    "VBS enclaves, which provide isolated execution environments for selected workloads.",
                            },
                        ]}
                    />

                    <ThirdHeader text="Hypervisor-Enforced Code Integrity (HVCI)" />
                    <div className="pt-4">
                        HVCI, also known as Memory Integrity, is one of the most visible VBS
                        features. Its job is to ensure that only trusted, validated code can
                        execute in kernel mode.
                    </div>
                    <div className="pt-2">
                        Windows achieves this by combining the Windows hypervisor with the
                        Secure Kernel, which runs in <InlineCode text="VTL1" />. The normal
                        Windows kernel and user-mode processes run in{" "}
                        <InlineCode text="VTL0" />, while security policy enforcement happens
                        in the more isolated environment.
                    </div>
                    <div className="pt-2">
                        At a high level, HVCI combines code integrity policy, hypervisor
                        memory enforcement, and second-stage address translation protections.
                        Once a kernel page is validated, the hypervisor can enforce strict
                        execution rules over it.
                    </div>
                    <div className="pt-2">
                        One of the most important results is the restriction of{" "}
                        <InlineCode text="W→X" /> transitions. Executable kernel pages should
                        not become writable later, and writable pages should not become
                        executable without going back through validation. That does not solve
                        every exploitation technique, but it raises the bar considerably.
                    </div>
                    <div className="pt-2">
                        If you want a deeper Windows-specific dive, Connor McGarr&apos;s{" "}
                        <StyledLink
                            href="https://connormcgarr.github.io/hvci/"
                            content="HVCI internals article"
                            textSize="text-md"
                        />
                        {" "}is excellent.
                    </div>

                    <SecondaryHeader text="Motivation Behind Nova" />
                    <div className="pt-4">
                        After spending time in both offensive and defensive research, I kept
                        coming back to the same observation: the ecosystem is clearly moving
                        toward virtualization-backed security, but most third-party security
                        tooling still treats the kernel as the highest point of control.
                    </div>
                    <div className="pt-2">
                        Anyone who has worked on Windows kernel exploitation or rootkits in
                        the last few years has felt the difference. The environment does not
                        look like it did five years ago. That is good news for defenders,
                        but it is also good for offensive research because it forces people
                        to explore harder and more interesting problems.
                    </div>
                    <div className="pt-2">
                        That shift is what motivated Nova. I wanted to explore what a
                        third-party, open-source, hypervisor-based defensive project could
                        look like, especially one aimed at protecting security-critical
                        components from a compromised kernel.
                    </div>

                    <SecondaryHeader text="Threat Model" />
                    <div className="pt-4">
                        Nova is designed around the assumption that kernel compromise may
                        already have happened. Concretely, the attacker may already have:
                    </div>
                    <BulletList
                        items={[
                            { content: "Kernel code execution." },
                            { content: "The ability to load a vulnerable driver (BYOVD)." },
                            { content: "The ability to modify kernel memory." },
                        ]}
                    />
                    <div className="pt-2">
                        Under those assumptions, traditional kernel-resident protections may
                        no longer be trustworthy. A hypervisor sits above the guest kernel
                        and can therefore enforce policies from a higher privilege layer.
                        That architectural advantage is what makes hypervisor-based defense
                        attractive here.
                    </div>

                    <SecondaryHeader text="Nova Architecture" />
                    <div className="pt-4">
                        My goal with Nova is to build a hypervisor-based defensive platform
                        that is open-source, usable, and practical for both research and
                        production-oriented experimentation. To get there, a few baseline
                        requirements matter:
                    </div>
                    <BulletList
                        items={[
                            {
                                content:
                                    "Compatibility with modern Windows 10, Windows 11, and Windows Server versions.",
                            },
                            {
                                content:
                                    "The ability to operate under VMware and Hyper-V, which are common both in research labs and production environments.",
                            },
                            {
                                content:
                                    "A clean interface that can integrate into existing environments without too much friction.",
                            },
                            {
                                content:
                                    "A design that aims for minimal performance overhead.",
                            },
                        ]}
                    />
                    <BlogImageFigure
                        src="/post-images/hypervisor-based-defense/nova_architecture.png"
                        alt="Nova architecture overview"
                        caption="Nova architecture overview"
                    />
                    
                    <div className="pt-2">
                        At a high level, Nova manages the guest while delegating lower-level
                        virtualization operations to the underlying hypervisor when needed.
                        The interesting part is what happens on top of that: by using EPT
                        hooks, Nova can treat sensitive memory ranges as policy-enforced
                        objects rather than just bytes that the guest kernel is free to
                        modify.
                    </div>

                    <ThirdHeader text="EPT Hooks" />
                    <div className="pt-4">
                        EPT hooks are one of the most useful primitives in this design.
                        Instead of patching the guest kernel directly, the hypervisor
                        changes EPT permissions so that specific accesses trigger EPT
                        violations. That forces the processor to VM-exit and gives the
                        hypervisor a chance to inspect the access and decide what to do next.
                    </div>
                    <div className="pt-2">
                        For example, if you want to watch a write to a sensitive region, you
                        can remove write permission from the relevant EPT entry. The guest
                        will continue running normally until it attempts that write. At that
                        point, the hypervisor receives control and can evaluate the context,
                        including which module performed the access and what memory was
                        touched.
                    </div>
                    <div className="pt-2">
                        Unlike traditional kernel hooks, EPT hooks operate outside the guest
                        operating system. That means they can remain effective even if the
                        guest kernel is already compromised. For a deeper implementation
                        walkthrough, memN0ps&apos;s{" "}
                        <StyledLink
                            href="https://memn0ps.github.io/hypervisors-for-memory-introspection-and-reverse-engineering/"
                            content="article on EPT-based introspection"
                            textSize="text-md"
                        />
                        {" "}is an excellent follow-up resource.
                    </div>

                    <ThirdHeader text="Hypervisor vs Kernel Level Threats" />
                    <div className="pt-4">
                        One of the most common ways attackers blind endpoint protections
                        today is by using a vulnerable driver, a kernel exploit, or a
                        rootkit to patch callbacks, remove hooks, tamper with ETW, or modify
                        the product itself. If the attacker controls the kernel, software
                        that lives only inside the kernel is in a very difficult position.
                    </div>
                    <div className="pt-2">
                        EPT-based enforcement changes that balance. A hypervisor can protect:
                    </div>
                    <BulletList
                        items={[
                            {
                                content:
                                    "Executable pages of an EPP driver or related process memory, preventing silent patching.",
                            },
                            {
                                content:
                                    "Important ETW-related structures by making unauthorized writes fault into the hypervisor.",
                            },
                            {
                                content:
                                    "Sensitive callback, callout, or routine lists by moving write authorization outside the guest kernel.",
                            },
                        ]}
                    />
                    <div className="pt-2">
                        That does not make kernel attacks obsolete, but it does significantly
                        raise the cost of using them to disable telemetry or blind security
                        tooling.
                    </div>
                    <div className="pt-4">
                        To better understand how that works in practice, let&apos;s see the following scenario and how Nova helps to mitigate it:
                    </div>
                    <BlogImageFigure
                        src="/post-images/hypervisor-based-defense/nova_example.png"
                        alt="Attack Scenario"
                        caption="Scenario: An attacker exploits a vulnerable driver to gain kernel R/W primitives to patch the callbacks list."
                    />
                    <div className="pt-2">
                        In this scenario, the attacker has already achieved kernel R/W primitives through a vulnerable driver. Their next step is to patch the callback list to remove the EPP callbacks.<br />
                        However, when the user uses Nova to protect the EPP driver address range, Nova monitors the callbacks list and when the attacker tries to patch it, Nova catches the write operation and denies it.
                    </div>

                    <ThirdHeader text="What Is Next?" />
                    <div className="pt-4">
                        This is a high level overview of what Nova has and what I want to achieve with it.
                        As you can tell, the project is still in its early stages and there is a lot more to implement, and the versions might shift a bit from the current plan.
                    </div>
                    <RoadmapTimeline
                        title="Nova's Roadmap"
                        items={[
                            {
                                version: "v1.0 | Initial Release",
                                description:
                                    "Hypervisor that works on Windows 10 and 11 versions, with support for VMware and minimal support of Hyper-V.",
                                features: [
                                    "EPT hooks",
                                    "Communication interface for third-party components",
                                    "Logging via ETW",
                                    "Event injection",  
                                    "Supporting running under VMware",
                                    "Basic support for running under Hyper-V"
                                ],
                                isCompleted: true,
                            },
                            {
                                version: "v1.0.1 | Hyper-V Fixes",
                                description:
                                    "Fixing Hyper-V compatibility issues and fully supporting Hyper-V environments (excluding with VBS enabled).",
                                features: [
                                    "Added handling of more VM-exit reasons that are relevant in Hyper-V environments",
                                    "Added handling of synthetic MSR accesses"
                                ],
                                bugfixes: [
                                    "Fixed Hyper-V support issues"
                                ],
                                isCurrentRelease: true
                            },
                            {
                                version: "v1.1 | Enhanced Interface",
                                description:
                                    "Make the interface more intuitive and easier to use for third-party defensive components, with a focus on improving the experience of writing EPT-based policies.",
                                features: [
                                    "Add an easy to use configuration system for EPT hooks",
                                    "Better logging system",
                                    "Automatically protect known sensitive structures such as ETW-related ones, callbacks lists",
                                    "Add documentation and examples for writing EPT-based policies"
                                ],
                                bugfixes: [
                                    "Add SAL annotations"
                                ]
                            },
                            {
                                version: "v1.2 | Support More Platforms",
                                description:
                                    "Expand support to VirtualBox, QEMU and KVM environments.",
                                features: [
                                    "Support VirtualBox",
                                    "Support QEMU",
                                    "Support KVM",
                                    "Add a CI pipeline to automatically test compatibility with all supported platforms"
                                ]
                            },
                            {
                                version: "v2.0 | AMD Support",
                                description:
                                    "Creating a version of Nova that works on AMD-V platforms, which requires an almost complete rework of the virtualization layer.",
                                features: [
                                    "Support AMD-V"
                                ]
                            },
                            {
                                version: "v2.1 | ARM Support",
                                description:
                                    "Creating a version of Nova that works on ARM platforms, which requires an almost complete rework of the virtualization layer.",
                                features: [
                                    "Support ARM"
                                ]
                            },
                            {
                                version: "v3.0 | VBS Compatibility",
                                description:
                                    "Reworking Nova&apos;s architecture to be compatible with VBS-enabled environments, which likely requires a significant redesign of the current implementation.",
                                features: [
                                    "Full compatibility with VBS-enabled environments",
                                    "Redesign of Nova architecture to work alongside the Windows hypervisor",
                                    "Add VBS-aware features",
                                    "Maintain support for Intel, AMD and ARM platforms"
                                ]
                            }
                        ]}
                    />
                    <div className="pt-2">
                        As you can tell, there is a lot more to be done. The current version, while it is stable and contains the core features it is far from being complete or where I want it to be.<br />
                        From the challenges of supporting different hypervisor platforms, to the architectural changes to support AMD-V, ARM and VBS there is so much to be done. With that being said, I still
                        believe that the current version is a solid foundation to build on and to learn from its code.
                    </div>

                    <SecondaryHeader text="Epilogue" />
                    <div className="pt-4">
                        This was intentionally a high-level overview of hypervisor-based
                        defense. I wanted it to be detailed enough to explain the underlying
                        ideas, while still remaining approachable for readers who are new to
                        virtualization.
                    </div>
                    <div className="pt-2">
                        If this area interests you, I strongly encourage you to explore
                        virtualization not only as an infrastructure primitive, but as a
                        security one. Even if you are coming from an offensive background,
                        asking how you can use virtualization to your advantage opens up a
                        surprisingly rich research space.
                    </div>
                    <div className="pt-2">
                        Finally, I want to thank <StyledLink
                            href="https://www.linkedin.com/in/matan-kotick/"
                            content="Matan Kotick"
                            textSize="text-md"
                        /> and <StyledLink
                            href="https://github.com/memn0ps"
                            content="memN0ps"
                            textSize="text-md"
                        /> for proof reading this article, <StyledLink
                            href="https://github.com/SinaKarvandi"
                            content="Sina Karvandi"
                            textSize="text-md"
                        />, <StyledLink
                            href="https://x.com/33y0re"
                            content="Connor McGarr"
                            textSize="text-md"
                        />, <StyledLink
                            href="https://github.com/tandasat"
                            content="Satoshi Tandasat"
                            textSize="text-md"
                        />, <StyledLink
                            href="https://x.com/aionescu"
                            content="Alex Ionescu"
                            textSize="text-md"
                        /> and many others whose work helped greatly in shaping my understanding of this space.
                    </div>
                </article>
            </div>
        </div>
    );
}
