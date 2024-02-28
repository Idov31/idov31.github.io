"use client";

import StyledLink from "@/components/StyledLink";
import SecondaryHeader, {BlogPrologue, InlineCode, NumberedList} from "@/components/BlogComponents";
import React from "react";

export default function CronosSleepObfuscation() {
    return (
        <div className="bg-bgInsideDiv p-6 rounded-xl h-full">
            <BlogPrologue title="timeout /t 31 && start evil.exe"
                          date="06.11.2022" projectLink="https://github.com/Idov31/Cronos" />
            <div className="pt-4">
                <article>
                    <SecondaryHeader text="Prologue"/>
                    <div className="pt-4">
                        Cronos is a new sleep obfuscation technique co-authored by
                        <StyledLink href="https://github.com/idov31" content=" idov31" textSize="text-md"/> and
                        <StyledLink href="https://github.com/janoglezcampos" content=" yxel" textSize="text-md"/>.

                        It is based on <StyledLink href="https://github.com/Cracked5pider" content="5pider's"
                                                   textSize="text-md"/>
                        <StyledLink href="https://github.com/Cracked5pider/Ekko" content=" Ekko " textSize="text-md"/>
                        and like it, it encrypts the process image with RC4 encryption and evades memory scanners by
                        also changing memory regions permissions from RWX to RW back and forth.

                        In this blog post, we will cover Cronos specifically and sleep obfuscation techniques in general
                        and explain why we need them and the common ground of any sleep obfuscation technique.

                        As always, the full code is available on <StyledLink href="https://github.com/idov31/Cronos"
                                                                             content=" GitHub" textSize="text-md"/> and
                        for any questions feel free to reach out on <StyledLink href="https://twitter.com/idov31"
                                                                                content="X (Twitter)"
                                                                                textSize="text-md"/>.
                    </div>
                    <SecondaryHeader text="Sleep Obfuscation In General"/>
                    <div className="pt-4">
                        To understand why sleep obfuscations are a need, we need to understand what problem they attempt
                        to solve. Detection capabilities have evolved over the years, we can see that more and more
                        companies going from using AV to EDRs as they provide more advanced detection capabilities and
                        attempt to find the hardest attackers to find. Besides that, also investigators have better
                        tools like <StyledLink href="https://github.com/hasherezade/pe-sieve"
                                               content="pe-sieve"
                                               textSize="text-md"/> that finds injected DLLs, hollowed processes and
                        shellcodes and that is a major problem for any attacker that attempts to hide their malware.

                        <div className="pt-2">
                            To solve this issue, people came up with sleep obfuscation techniques and all of them have a
                            basic idea: As long as the current piece of malware (whether it is DLL, EXE or shellcode)
                            isn&apos;t doing any important &quot;work&quot; (for example, when an agent don&apos;t have any task from the C2
                            or backdoor that just checks in once in a while) it should be encrypted, when people start
                            realizing that they came up with a technique that will encrypt the process image and decrypt
                            it when it needs to be activated.
                        </div>

                        <div className="pt-2">
                            One of the very first techniques I got to know is <StyledLink
                            href="https://github.com/JLospinoso/gargoyle"
                            content="Gargoyle "
                            textSize="text-md"/>
                            which is an amazing technique for marking a process as non-executable and using the ROP
                            chain to make it executable again. This worked great until scanners began to adapt and began
                            looking also for non-executable memory regions, but in this game of cops and thieves, the
                            attackers adapted again and started using a single byte XOR to encrypt the malicious part or
                            the whole image an example for it is <StyledLink
                            href="https://github.com/SolomonSklash/SleepyCrypt"
                            content="SleepyCrypt"
                            textSize="text-md"/>. SleepyCrypt not only
                            adds encryption but also supports x64 binaries (the original Gargoyle supports only x86 but
                            Waldo-IRC created an <StyledLink href="https://github.com/waldo-irc/YouMayPasser"
                                                             content="x64 version of Gargoyle"
                                                             textSize="text-md"/> but, you guessed it, memory scanners
                            found a solution to that as well by doing single XOR brute force on memory regions.
                        </div>
                        <div className="pt-2">
                            Now that we have the background and understand <b>WHY</b> sleep obfuscations exist let&apos;s
                            understand
                            what has changed and what sleep obfuscation techniques we have nowadays.
                        </div>
                    </div>
                    <SecondaryHeader text="Modern Sleep Obfuscations"/>
                    <div className="pt-4">
                        Today (speaking in 2022) we have memory scanners that can brute force single-byte XOR encryption
                        and detect malicious programs even when they do not have any executable rights, what can be done
                        next?

                        <div className="pt-2">
                            The answer starts to become clearer in <StyledLink
                            href="https://github.com/SecIdiot/FOLIAGE"
                            content="Foliage"
                            textSize="text-md"/>, which uses not only
                            heavier obfuscation than single-byte XOR but also a neat trick to trigger the ROP chain to
                            change the memory regions&apos; permission using <InlineCode text="NtContinue"/> and context.
                        </div>
                        <div className="pt-2">
                            Later on, <StyledLink href="https://github.com/Cracked5pider/Ekko"
                                                  content="Ekko"
                                                  textSize="text-md"/> came out and added 2 important features:
                            One of them is to RC4 encrypt the process image using an undocumented function
                            <InlineCode text=" SystemFunction032"/>, and the other one is to address and fix the soft
                            spot of every sleep technique so far: Stabilize the ROP using a small and very meaningful
                            change to the RSP register.
                        </div>

                        <div className="pt-2">
                            To conclude the modern sleep obfuscation section we will also talk about
                            <StyledLink href="https://github.com/janoglezcampos/DeathSleep"
                                        content=" DeathSleep"
                                        textSize="text-md"/> a technique that kills the current thread after saving its
                            CPU state and stack and then restores them. DeathSleep also helped a lot during the creation
                            of Cronos.
                        </div>
                        <div className="pt-2">
                            Now, it is understandable where we are heading with this and combine all the knowledge we
                            have
                            accumulated so far to create Cronos.
                        </div>
                    </div>
                    <SecondaryHeader text="Cronos"/>
                    <div className="pt-4">
                        The main logic of Cronos is pretty simple:

                        <NumberedList items={[
                            {
                                content: "Changing the image's protection to RW."
                            },
                            {
                                content: "Encrypt the image."
                            },
                            {
                                content: "Decrypt the image."
                            },
                            {
                                content: "Add execution privileges to the image."
                            }
                        ]}/>

                        <div className="pt-2">
                            To achieve this we need to do several things like encrypting somehow the image with a
                            function, choosing which kind of timer to use and most importantly finding a way to execute
                            code when the image is decrypted.
                        </div>
                        <div className="pt-2">
                            Finding an encryption function was easy, choosing <InlineCode text="SystemFunction032"/> was
                            an obvious choice since it is well used (also in Ekko) and also documented by Benjamin Delpy
                            in <StyledLink href="https://blog.gentilkiwi.com/cryptographie/api-systemfunction-windows"
                                           content="his article"
                                           textSize="text-md"/> and many other places.
                        </div>

                        <div className="pt-2">
                            One may ask &quot;Why to use a function that can be used as a strong IoC when you can do custom
                            or XOR encryption?&quot; the honest answer is that it will be much easier to use it in the ROP
                            later on (spoiler alert) than implementing strong and good encryption.
                        </div>
                        <div className="pt-2">
                            Now, that we have an encryption function we need to have timers that can execute an APC
                            function of our choosing. For that, I chose waitable timers because they are well-documented
                            , easy and stable to use and easy to trigger - all that needs to be done is to call any
                            alertable sleep function (e.g. <InlineCode text="SleepEx"/>).
                        </div>
                        <div className="pt-2">
                            All we have left to do is to find a way to execute an APC that will trigger the sleeping
                            function, the problem is that the code has to run regardless of the image&apos;s state (whether
                            has executable rights, is encrypted, etc.) and the obvious solution is to use an ROP chain
                            that will execute the sleep to trigger the APC.
                        </div>
                        <div className="pt-2">
                            For the final stage, we used the NtContinue trick from Foliage to execute the different
                            stages of sleep obfuscation <InlineCode text="(RW -> Encrypt -> Decrypt -> RWX)"/>.
                        </div>
                    </div>

                    <SecondaryHeader text="Conclusion"/>
                    <div className="pt-4">
                        This was a fun project to make, and we were able to make it thanks to the amazing projects
                        mentioned here every single one of them created another piece to get us where we are here.

                        <p>I hope that you enjoyed the blog and would love to hear what you think about it!</p>
                    </div>
                </article>
            </div>
        </div>
    );
}