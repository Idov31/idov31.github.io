import React from "react";
import Image from "next/image";
import StyledLink from "@/components/StyledLink";

interface BlogImageFigureProps {
    src: string;
    alt: string;
    caption?: string;
    sourceHref?: string;
}

export default function BlogImageFigure({
    src,
    alt,
    caption,
    sourceHref,
}: BlogImageFigureProps) {
    return (
        <figure className="pt-4 pb-2">
            <div className="flex justify-center">
                <Image
                    src={src}
                    alt={alt}
                    width={0}
                    height={0}
                    sizes="100vw"
                    className="h-auto w-auto max-w-full rounded-xl"
                />
            </div>
            {(caption || sourceHref) && (
                <figcaption className="pt-2 text-sm italic text-txtSubHeader text-center">
                    {caption}
                    {caption && sourceHref ? " | " : ""}
                    {sourceHref && (
                        <StyledLink
                            href={sourceHref}
                            content="View source"
                            textSize="text-sm"
                        />
                    )}
                </figcaption>
            )}
        </figure>
    );
}
