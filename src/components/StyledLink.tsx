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

interface StyledLinkProps {
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

export default function StyledLink({href, content, textSize = "text-md"}: StyledLinkProps) {
    return (
        <Link
            className={`text-txtLink ${textSize} hover:underline underline-offset-2 transition-colors duration-200`}
            href={href}
        >
            {content}
        </Link>
    );
}

export function StyledHeaderLink({href, content}: StyledHearderLinkProps) {
    return (
        <Link
            className="transition-colors duration-200 hover:text-txtSubHeader"
            href={href}
        >
            {content}
        </Link>
    );
}

export function StyledBarLink({href, content, mr = 2, isBurger = false}: StyledBarLinkProps) {
    return (
        <Link
            className={`mb-2 mr-${mr} ${isBurger ? "text-2xl" : "text-xl"} transition duration-200
                        hover:text-txtSubHeader`}
            href={href}
        >
            {content}
        </Link>
    );
}

export function ImageLink({href, imagePath, alt, width = 100, height = 100}: ImageLinkProps) {
    return (
        <a href={href} target="_blank" rel="noopener noreferrer">
            <Image src={imagePath} alt={alt} width={width} height={height}/>
        </a>
    );
}
