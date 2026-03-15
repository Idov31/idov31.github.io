import React, {useState} from "react";
import {CodeBlock, dracula} from "react-code-blocks";
import StyledLink, {ImageLink} from "@/components/StyledLink";

interface SecondaryHeaderProps {
    text: string;
}

interface CodeProps {
    text: string;
    message?: string;
    language?: string;
    isMessageToggled?: boolean;
}

interface InlineCodeProps {
    text: string;
}

interface ListItem {
    content: string;
    linkContent?: string;
    link?: string;
}

interface BulletListProps {
    items: ListItem[];
}

interface NumberedListProps {
    items: ListItem[];
}

interface BlogPrologueProps {
    title: string;
    date: string;
    projectLink?: string;
}

export default function SecondaryHeader({text}: SecondaryHeaderProps) {
    const id = text.toLowerCase().split(' ').join('-');
    return (
        <div className="pt-6 pb-3">
            <hr className="divider-glow"/>
            <h2 id={id} className="text-2xl font-semibold text-txtSubHeader pt-1">{text}</h2>
        </div>
    );
}

export function ThirdHeader({text}: SecondaryHeaderProps) {
    const id = text.toLowerCase().split(' ').join('-');
    return (
        <div className="pt-4 pb-2">
            <h3 id={id} className="text-xl font-semibold text-txtSubHeader">{text}</h3>
        </div>
    );
}

export function Code({text, message = "NaN", language = "cpp", isMessageToggled = false}: CodeProps) {
    const [isOpen, setIsOpen] = useState(false);

    const toggleOpen = () => {
        setIsOpen(!isOpen);
    };

    if (isMessageToggled) {
        return (
            <div className="pt-4 pb-4 text-sm lg:text-md">
                <button
                    className="bg-bgSemiTransparent text-txtHeader w-full py-3 text-left pl-4 rounded-t-lg
                               border border-borderSubtle hover:border-borderMid transition-colors"
                    onClick={toggleOpen}
                >
                    {isOpen ? `${message} [Collapse]` : `${message} [Expand]`}
                </button>
                {isOpen && (
                    <div className="code-block-wrapper">
                        <CodeBlock
                            text={text}
                            language={language}
                            showLineNumbers={true}
                            theme={dracula}
                        />
                    </div>
                )}
            </div>
        );
    }

    return (
        <div className="pt-4 pb-4 text-sm lg:text-md">
            <div className="code-block-wrapper">
                <CodeBlock
                    text={text}
                    language={language}
                    showLineNumbers={true}
                    theme={dracula}
                />
            </div>
        </div>
    );
}

export function InlineCode({text}: InlineCodeProps) {
    return (
        <code className="text-txtInlineCode bg-bgSurface px-1.5 py-0.5 rounded text-sm font-mono">{text}</code>
    );
}

export function BlogPrologue({title, date, projectLink} : BlogPrologueProps) {
    return (
        <div className="pb-8 border-b border-borderSubtle">
            <div className="badge badge-purple mb-3">{date}</div>
            <h1 className="text-3xl lg:text-4xl font-bold text-txtHeader leading-tight">{title}</h1>
            <div className="flex items-center gap-2 mt-3">
                <span className="text-txtMuted text-sm">Ido Veltzman</span>
            </div>
            {projectLink && (
                <div className="flex flex-row gap-4 pt-5 flex-wrap">
                    <ImageLink href={projectLink} imagePath="/post-images/GithubStar.svg" alt="star"/>
                    <ImageLink href={`${projectLink}/fork`} imagePath="/post-images/GithubFork.svg" alt="fork"/>
                    <ImageLink
                        href="https://github.com/Idov31"
                        imagePath="/post-images/GithubFollow.svg"
                        alt="follow"
                        width={125}
                        height={150}
                    />
                </div>
            )}
        </div>
    );
}

export const BulletList: React.FC<BulletListProps> = ({items}) => {
    return (
        <ul className="list-none pl-4 pt-4 space-y-2">
            {items.map((item, index) => (
                <li key={index} className="flex gap-2">
                    <span className="text-accentPurple mt-1 flex-shrink-0">▸</span>
                    <p className="text-txtRegular">
                        {item.link && item.linkContent ? (
                            <>
                                {item.content}
                                <StyledLink href={item.link} content={item.linkContent} textSize="text-md"/>
                            </>
                        ) : (
                            item.content
                        )}
                    </p>
                </li>
            ))}
        </ul>
    );
};

export const NumberedList: React.FC<NumberedListProps> = ({items}) => {
    return (
        <ol className="list-none pl-4 pt-4 space-y-2 counter-reset-none">
            {items.map((item, index) => (
                <li key={index} className="flex gap-3">
                    <span className="text-accentPurple font-mono text-sm mt-0.5 flex-shrink-0 w-5">
                        {index + 1}.
                    </span>
                    <p className="text-txtRegular">
                        {item.link && item.linkContent ? (
                            <>
                                {item.content}
                                <StyledLink href={item.link} content={item.linkContent} textSize="text-md"/>
                            </>
                        ) : (
                            item.content
                        )}
                    </p>
                </li>
            ))}
        </ol>
    );
};
