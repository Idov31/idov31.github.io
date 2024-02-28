import {StyledHeaderLink} from "@/components/StyledLink";
import Image from "next/image";

interface BlogPostProps {
    href: string;
    headerContent: string;
    subHeaderContent: string;
    imagePath: string;
    imageAlt: string;
    imageWidth: number;
    imageHeight: number;
    postContent: string;
    sub?: boolean;
}

export default function BlogPost({
                                     href,
                                     headerContent,
                                     subHeaderContent,
                                     imagePath,
                                     imageAlt,
                                     imageWidth,
                                     imageHeight,
                                     postContent,
                                     sub = true
                                 }: BlogPostProps) {
    return (
        <div className={`${sub ? 'pt-8' : ''} pb-6 border-b-4 border-dotted border-txtLink`}>
            <h1 className="text-4xl text-txtHeader"><StyledHeaderLink
                href={href}
                content={headerContent}/>
            </h1>
            <div className="flex flex-row justify-between">
                <h2 className="text-2xl text-txtSubHeader pt-2">{subHeaderContent}</h2>
                <Image src={imagePath} alt={imageAlt} width={imageWidth} height={imageHeight}/>
            </div>
            <p className="text-xl pt-3">{postContent}</p>
        </div>
    );
}