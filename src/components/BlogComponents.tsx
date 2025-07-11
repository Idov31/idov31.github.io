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
        <div className="pt-4 pb-3 border-b border-txtLink">
            <h2 id={id} className="text-3xl text-txtSubHeader pt-2">{text}</h2>
        </div>
    );
}

export function ThirdHeader({text}: SecondaryHeaderProps) {
    const id = text.toLowerCase().split(' ').join('-');
    return (
        <div className="pt-4 pb-3 border-b border-txtLink">
            <h3 id={id} className="text-2xl text-txtSubHeader pt-2">{text}</h3>
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
                <button className="bg-bgSemiTransparent text-txtHeader w-full py-4 text-left pl-3.5"
                        onClick={toggleOpen}>
                    {isOpen ? `${message} [Drop]` : `${message} [Expand]`}
                </button>
                {isOpen && (
                    <CodeBlock
                        text={text}
                        language={language}
                        showLineNumbers={true}
                        theme={dracula}
                    />
                )}
            </div>
        );
    } else {
        return (
            <div className="pt-4 pb-4 text-sm lg:text-md">
                <CodeBlock
                    text={text}
                    language={language}
                    showLineNumbers={true}
                    theme={dracula}
                />
            </div>
        );
    }
}

export function InlineCode({text}: InlineCodeProps) {
    return (
        <code className="text-txtInlineCode">{text}</code>
    );
}

export function BlogPrologue({title, date, projectLink} : BlogPrologueProps) {
    return (
        <div className="pb-6 border-b-4 border-dotted border-txtLink">
            <h1 className="text-4xl text-txtHeader">{title}</h1>
            <div className="flex flex-row justify-between">
                <h2 className="text-2xl text-txtSubHeader pt-2">Ido Veltzman | {date}</h2>
            </div>
            <div className="flex flex-row justify-between pt-4 md:w-1/2 lg:w-1/7">
                <ImageLink href={projectLink} imagePath="/post-images/GithubStar.svg"
                           alt="star"/>
                <ImageLink href={`${projectLink}/fork`} imagePath="/post-images/GithubFork.svg"
                           alt="fork"/>
                <ImageLink href="https://github.com/Idov31" imagePath="/post-images/GithubFollow.svg"
                           alt="follow" width={125} height={150}/>
            </div>
        </div>
    );
}

export const BulletList: React.FC<BulletListProps> = ({items}) => {
    return (
        <ul className="list-disc pl-10 pt-4">
            {items.map((item, index) => (
                <li key={index} className="mb-4">
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
        </ul>
    );
};

export const NumberedList: React.FC<NumberedListProps> = ({items}) => {
    return (
        <ol className="list-decimal pl-10 pt-4">
            {items.map((item, index) => (
                <li key={index} className="mb-4">
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