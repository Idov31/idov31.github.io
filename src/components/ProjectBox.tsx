import Image from "next/image";

interface ProjectBoxProps {
    imagePath: string;
    projectLink: string;
    projectName: string;
    description: string;
}

export default function ProjectBox({imagePath, projectLink, projectName, description}: ProjectBoxProps) {
    return (
        <a
            href={projectLink}
            target="_blank"
            rel="noopener noreferrer"
            className="block card-surface rounded-xl p-5 hover:glow transition-all duration-300 group"
        >
            <div className="flex flex-col h-full">
                <div className="flex items-center gap-3 mb-3">
                    <Image
                        src={imagePath}
                        alt={projectName}
                        width={40}
                        height={40}
                        className="rounded-lg object-contain"
                    />
                    <h3 className="text-txtHeader font-semibold text-lg group-hover:text-txtSubHeader transition-colors">
                        {projectName}
                    </h3>
                </div>
                <p className="text-txtMuted text-sm leading-relaxed flex-1">{description}</p>
                <span className="inline-flex items-center gap-1 mt-3 text-txtLink text-xs font-medium
                                 group-hover:gap-2 transition-all duration-200">
                    View on GitHub <span>→</span>
                </span>
            </div>
        </a>
    );
}
