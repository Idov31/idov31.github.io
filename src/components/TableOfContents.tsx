"use client";

import React, {useEffect, useRef, useState} from "react";
import StyledLink from "@/components/StyledLink";

type TocItem = {
    id: string;
    title: string;
    level: number;
    children: TocItem[];
};

function buildTocTree(headings: HTMLHeadingElement[]) {
    const rootItems: TocItem[] = [];
    const stack: TocItem[] = [];

    for (const heading of headings) {
        const title = heading.textContent?.trim();

        if (!heading.id || !title) {
            continue;
        }

        const item: TocItem = {
            id: heading.id,
            title,
            level: Number.parseInt(heading.tagName.slice(1), 10),
            children: [],
        };

        while (stack.length > 0 && stack[stack.length - 1].level >= item.level) {
            stack.pop();
        }

        if (stack.length === 0) {
            rootItems.push(item);
        } else {
            stack[stack.length - 1].children.push(item);
        }

        stack.push(item);
    }

    return rootItems;
}

function TocList({items}: {items: TocItem[]}) {
    return (
        <ul className="space-y-2">
            {items.map((item) => (
                <li key={item.id}>
                    <StyledLink href={`#${item.id}`} content={item.title} textSize="text-sm"/>
                    {item.children.length > 0 && (
                        <div className="pl-5 pt-2">
                            <TocList items={item.children}/>
                        </div>
                    )}
                </li>
            ))}
        </ul>
    );
}

export default function TableOfContents() {
    const rootRef = useRef<HTMLDivElement>(null);
    const [items, setItems] = useState<TocItem[]>([]);
    const [hasScanned, setHasScanned] = useState(false);

    useEffect(() => {
        const article = rootRef.current?.closest("article");

        if (!article) {
            setHasScanned(true);
            return;
        }

        const headings = Array.from(
            article.querySelectorAll("h2[id], h3[id], h4[id]"),
        ) as HTMLHeadingElement[];

        setItems(buildTocTree(headings.filter((heading) => heading.id !== "table-of-contents")));
        setHasScanned(true);
    }, []);

    if (hasScanned && items.length === 0) {
        return null;
    }

    return (
        <div ref={rootRef} className="mb-8 rounded-2xl border border-borderSubtle bg-bgInsideDiv p-5">
            <div className="badge badge-purple mb-3">Table Of Contents</div>
            <nav aria-label="Table of contents">
                <TocList items={items}/>
            </nav>
        </div>
    );
}