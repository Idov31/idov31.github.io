import Link from "next/link";
import React from "react";
import Image from "next/image";

interface StyledBarLinkProps {
    href: string;
    content: string;
    mr?: number;
    isBurger?: boolean;
}

interface StyledHearderLinkProps {
    href: string;
    content: string;
}

interface  StyledLinkProps {
    href: string;
    content: string;
    textSize?: string;
}

interface ImageLinkProps {
    href: string;
    imagePath: string;
    alt: string;
    width?: number;
    height?: number;
}

export default function StyledLink({href, content, textSize = "text-xl"}: StyledLinkProps) {
    return (
        <Link className={`text-txtLink ${textSize} transition duration-500 hover:border-b-2
                        hover:border-current`} href={href}>{content}</Link>
    );
}

export function StyledHeaderLink({href, content}: StyledHearderLinkProps) {
    return (
        <Link className={`transition duration-500 hover:border-b-2 hover:border-current`} href={href}>{content}</Link>
    );
}

export function StyledBarLink({href, content, mr = 2, isBurger = false}: StyledBarLinkProps) {
    return (
        <Link className={`mb-2 mr-${mr} ${isBurger ? "text-2xl" : "text-xl"} transition duration-500 hover:border-b-2
                        hover:border-current`} href={href}>{content}</Link>
    );
}

export function ImageLink({href, imagePath, alt, width = 100, height = 100}: ImageLinkProps) {
    return (
        <a href={href}>
            <Image src={imagePath} alt={alt} width={width} height={height} />
        </a>
    );
}