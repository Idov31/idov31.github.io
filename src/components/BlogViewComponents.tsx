import Link from "next/link";
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
                                     postContent,
                                 }: BlogPostProps) {
    return (
        <Link href={href} className="block group">
            <article className="card-surface rounded-xl p-5 flex flex-col sm:flex-row gap-4 transition-all duration-300">
                <div className="sm:w-24 sm:h-24 flex-shrink-0 rounded-lg overflow-hidden bg-bgSurface flex items-center justify-center">
                    <Image
                        src={imagePath}
                        alt={imageAlt}
                        width={96}
                        height={96}
                        className="object-contain w-full h-full p-1"
                    />
                </div>
                <div className="flex flex-col flex-1 min-w-0">
                    <div className="badge badge-purple mb-2 w-fit">{subHeaderContent}</div>
                    <h2 className="text-lg font-semibold text-txtHeader group-hover:text-txtSubHeader
                                   transition-colors duration-200 leading-snug mb-1">
                        {headerContent}
                    </h2>
                    <p className="text-txtMuted text-sm leading-relaxed line-clamp-2">{postContent}</p>
                    <span className="inline-flex items-center gap-1 mt-2 text-txtLink text-xs font-medium
                                     group-hover:gap-2 transition-all duration-200">
                        Read more <span>→</span>
                    </span>
                </div>
            </article>
        </Link>
    );
}
