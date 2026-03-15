"use client";

import React, { useState } from "react";

interface RoadmapItem {
    version: string;
    description: string;
    features?: string[] | null;
    bugfixes?: string[] | null;
    isCurrentRelease?: boolean;
    isCompleted?: boolean;
}

interface RoadmapTimelineProps {
    title?: string;
    description?: string;
    items: RoadmapItem[];
}

export default function RoadmapTimeline({
    title = "Roadmap",
    description = "A high-level view of the milestones I want to achieve.",
    items,
}: RoadmapTimelineProps) {
    const [isCollapsed, setIsCollapsed] = useState(false);

    return (
        <section className="pt-6" aria-labelledby="roadmap-title">
            <div className="rounded-2xl border border-txtLink/30 bg-bgSemiTransparent p-5 md:p-7">
                <div className={isCollapsed ? "pb-0" : "pb-6"}>
                    <div className="flex items-start justify-between gap-4">
                        <div>
                            <h4
                                id="roadmap-title"
                                className="text-2xl text-txtHeader"
                            >
                                {title}
                            </h4>
                            {!isCollapsed && (
                                <p className="pt-2 text-sm text-txtSubHeader md:text-base">
                                    {description}
                                </p>
                            )}
                        </div>

                        <button
                            type="button"
                            onClick={() => setIsCollapsed((current) => !current)}
                            aria-expanded={!isCollapsed}
                            aria-controls="roadmap-content"
                            aria-label={isCollapsed ? "Expand roadmap" : "Collapse roadmap"}
                            className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full border border-txtLink/30 text-txtLink transition duration-300 hover:bg-black/10"
                        >
                            <span
                                className={`text-lg leading-none transition-transform duration-300 ${isCollapsed ? "rotate-180" : "rotate-0"}`}
                            >
                                ^
                            </span>
                        </button>
                    </div>
                </div>

                {!isCollapsed && (
                    <div id="roadmap-content" className="relative pl-8 md:pl-10">
                        <div className="absolute bottom-0 left-3 top-0 w-px bg-txtLink/40 md:left-4" />

                        <div className="space-y-6">
                            {items.map((item) => (
                                <article key={item.version} className="relative">
                                    <div className="absolute left-[-1.95rem] top-5 h-4 w-4 rounded-full border-2 border-txtLink bg-bgInsideDiv md:left-[-2.45rem]" />

                                    <div className="rounded-xl border border-txtLink/20 bg-bgInsideDiv p-5 shadow-sm">
                                        <div className="flex flex-col gap-2 border-b border-txtLink/20 pb-4 md:flex-row md:items-center md:justify-between">
                                            <h5 className="text-xl text-txtHeader">
                                                {item.version}
                                            </h5>
                                            <div className="flex flex-wrap gap-2">
                                                {item.isCurrentRelease && (
                                                    <span className="w-fit rounded-full border border-emerald-400/40 bg-emerald-400/10 px-3 py-1 text-xs uppercase tracking-[0.2em] text-emerald-300">
                                                        Current Release
                                                    </span>
                                                )}
                                                {item.isCompleted && (
                                                    <span className="w-fit rounded-full border border-sky-400/40 bg-sky-400/10 px-3 py-1 text-xs uppercase tracking-[0.2em] text-sky-300">
                                                        Completed
                                                    </span>
                                                )}
                                                {!item.isCurrentRelease && !item.isCompleted && (
                                                    <span className="w-fit rounded-full border border-txtLink/30 px-3 py-1 text-xs uppercase tracking-[0.2em] text-txtLink">
                                                        Milestone
                                                    </span>
                                                )}
                                            </div>
                                        </div>

                                        <p className="pt-4 text-base text-txtSubHeader">
                                            {item.description}
                                        </p>

                                        {((item.features && item.features.length > 0) ||
                                            (item.bugfixes && item.bugfixes.length > 0)) && (
                                            <div className="grid gap-4 pt-4 md:grid-cols-2">
                                                {item.features && item.features.length > 0 && (
                                                    <div>
                                                        <p className="pb-3 text-sm uppercase tracking-[0.2em] text-txtLink">
                                                            Features
                                                        </p>
                                                        <ul className="grid gap-3">
                                                            {item.features.map((feature) => (
                                                                <li
                                                                    key={feature}
                                                                    className="rounded-lg border border-txtLink/15 bg-black/10 px-4 py-3 text-sm text-txtHeader"
                                                                >
                                                                    {feature}
                                                                </li>
                                                            ))}
                                                        </ul>
                                                    </div>
                                                )}

                                                {item.bugfixes && item.bugfixes.length > 0 && (
                                                    <div>
                                                        <p className="pb-3 text-sm uppercase tracking-[0.2em] text-txtLink">
                                                            Bugfixes
                                                        </p>
                                                        <ul className="grid gap-3">
                                                            {item.bugfixes.map((bugfix) => (
                                                                <li
                                                                    key={bugfix}
                                                                    className="rounded-lg border border-amber-300/20 bg-amber-200/5 px-4 py-3 text-sm text-txtHeader"
                                                                >
                                                                    {bugfix}
                                                                </li>
                                                            ))}
                                                        </ul>
                                                    </div>
                                                )}
                                            </div>
                                        )}
                                    </div>
                                </article>
                            ))}
                        </div>
                    </div>
                )}
            </div>
        </section>
    );
}