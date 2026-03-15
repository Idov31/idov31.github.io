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
    projectLink: string;
}

export default function SecondaryHeader({text}: SecondaryHeaderProps) {
    const id = text.toLowerCase().split(' ').join('-');
    return (
        <div className="pt-6 pb-3">
            <h2 id={id} className="text-2xl sm:text-3xl font-cinzel text-txtSubHeader pt-2 pb-2
                                   border-b border-borderAccent">
                {text}
            </h2>
        </div>
    );
}

export function ThirdHeader({text}: SecondaryHeaderProps) {
    const id = text.toLowerCase().split(' ').join('-');
    return (
        <div className="pt-4 pb-2">
            <h3 id={id} className="text-xl sm:text-2xl font-cinzel text-txtSubHeader pt-2 pb-2
                                   border-b border-borderPurple">
                {text}
            </h3>
        </div>
    );
}

export function Code({text, message = "NaN", language = "cpp", isMessageToggled = false}: CodeProps) {
    const [isOpen, setIsOpen] = useState(false);

    if (isMessageToggled) {
        return (
            <div className="pt-4 pb-4 text-sm lg:text-md">
                <button
                    className="w-full py-3 pl-4 text-left text-txtHeader font-medium
                               bg-bgCard border border-borderPurple rounded-t-lg
                               hover:bg-borderPurple transition-colors duration-200"
                    onClick={() => setIsOpen(!isOpen)}
                >
                    <span className="text-txtMuted mr-2">{isOpen ? '▾' : '▸'}</span>
                    {isOpen ? `${message} [Collapse]` : `${message} [Expand]`}
                </button>
                {isOpen && (
                    <div className="rounded-b-lg overflow-hidden border border-t-0 border-borderPurple">
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
        <div className="pt-4 pb-4 text-sm lg:text-md rounded-lg overflow-hidden border border-borderPurple">
            <CodeBlock
                text={text}
                language={language}
                showLineNumbers={true}
                theme={dracula}
            />
        </div>
    );
}

export function InlineCode({text}: InlineCodeProps) {
    return (
        <code className="text-txtInlineCode bg-bgCard px-1.5 py-0.5 rounded text-sm font-mono">
            {text}
        </code>
    );
}

export function BlogPrologue({title, date, projectLink}: BlogPrologueProps) {
    return (
        <div className="pb-8">
            <p className="section-label mb-3">Blog Post</p>
            <h1 className="text-3xl sm:text-4xl lg:text-5xl font-cinzel text-txtHeader leading-tight">
                {title}
            </h1>
            <div className="flex flex-wrap items-center gap-4 mt-4">
                <p className="text-txtMuted text-sm">Ido Veltzman &nbsp;·&nbsp; {date}</p>
            </div>
            <div className="flex flex-row gap-4 pt-4">
                <ImageLink href={projectLink} imagePath="/post-images/GithubStar.svg" alt="star"/>
                <ImageLink href={`${projectLink}/fork`} imagePath="/post-images/GithubFork.svg" alt="fork"/>
                <ImageLink href="https://github.com/Idov31" imagePath="/post-images/GithubFollow.svg"
                           alt="follow" width={125} height={150}/>
            </div>
            <div className="terminal-divider mt-6"/>
        </div>
    );
}

export const BulletList: React.FC<BulletListProps> = ({items}) => {
    return (
        <ul className="list-none pl-2 pt-4 space-y-2">
            {items.map((item, index) => (
                <li key={index} className="flex items-start gap-3">
                    <span className="w-1.5 h-1.5 rounded-full bg-txtLink flex-shrink-0 mt-2"/>
                    <p className="text-txtRegular leading-relaxed">
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
        <ol className="list-decimal pl-6 pt-4 space-y-2">
            {items.map((item, index) => (
                <li key={index} className="text-txtRegular leading-relaxed pl-2">
                    <p>
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
