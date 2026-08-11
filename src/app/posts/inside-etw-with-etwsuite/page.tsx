'use client';

import { useEffect } from 'react';
import SecondaryHeader, { BlogPrologue, BulletList } from '@/components/BlogComponents';
import StyledLink from '@/components/StyledLink';
import TableOfContents from '@/components/TableOfContents';

export default function InsideEtwWithEtwSuite() {
    useEffect(() => {
        document.title = 'Inside Event Tracing for Windows with EtwSuite';
    }, []);

    return (
        <div className="card-surface rounded-xl p-6 lg:p-8 animate-fade-in post-content">
            <BlogPrologue
                title="Inside Event Tracing for Windows with EtwSuite"
                date="09.08.2026"
                projectLink="https://github.com/Idov31/EtwSuite"
            />
            <div className="pt-4">
                <article>
                    <TableOfContents />

                    <div className="drop-caps pt-4">
                        Event Tracing for Windows (ETW) is one of the richest sources of
                        telemetry available on Windows. It can expose activity from the
                        kernel, drivers, services, frameworks, and applications, but the
                        provider models, sessions, and metadata can make it difficult to
                        approach as a researcher or defender.
                    </div>
                    <div className="pt-2">
                        In this video, I walk through the ETW ecosystem, look at what happens
                        when providers register and sessions start, and demonstrate how
                        EtwSuite can turn those events into a practical research workflow.
                    </div>

                    <div className="pt-6">
                        <div className="aspect-video overflow-hidden rounded-xl border border-borderSubtle bg-bgSurface">
                            <iframe
                                className="h-full w-full"
                                src="https://www.youtube.com/embed/a5hvDNZeRIw?si=waY0h4i9sLe2FCIJ"
                                title="Inside Event Tracing for Windows with EtwSuite"
                                allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share"
                                referrerPolicy="strict-origin-when-cross-origin"
                                allowFullScreen
                            />
                        </div>
                    </div>

                    <SecondaryHeader text="What the Video Covers" />
                    <BulletList
                        items={[
                            {
                                content:
                                    'The ETW architecture: providers, controllers, consumers, and the session infrastructure that connects them.',
                            },
                            {
                                content:
                                    'Classic, WPP, manifest-based, and TraceLogging providers, including the practical limitations and access restrictions that matter when consuming them.',
                            },
                            {
                                content:
                                    'How ETW is initialized during boot, how providers register, and how a controller creates a tracing session.',
                            },
                            {
                                content:
                                    'Using EtwSuite to find providers, consume live events, filter results, and record or export traces for later analysis.',
                            },
                            {
                                content:
                                    'A UAC-bypass case study that compares benign and malicious requests to identify useful detection signals.',
                            },
                        ]}
                    />

                    <SecondaryHeader text="EtwSuite as a Research Tool" />
                    <div className="pt-4">
                        <StyledLink
                            href="https://github.com/Idov31/EtwSuite"
                            content="EtwSuite"
                            textSize="text-md"
                        />{' '}
                        is a Windows-native ETW inspection suite built to make the full
                        workflow easier to work with from one desktop application. You can
                        browse registered providers, inspect their metadata, collect live
                        events, and save recordings as ETL, JSON, or CSV files.
                    </div>
                    <div className="pt-2">
                        That combination is especially useful when exploring an unfamiliar
                        provider. Rather than writing a consumer before knowing whether a
                        provider exposes the fields you need, you can inspect the manifest,
                        generate a controlled event, and compare the resulting telemetry
                        directly in the tool.
                    </div>

                    <SecondaryHeader text="From Telemetry to Detection" />
                    <div className="pt-4">
                        The demonstration uses the Microsoft Antimalware UAC Scan provider
                        to compare a normal elevation request with a UAC bypass. By examining
                        the requesting process, request type, trust state, auto-elevation
                        information, command line, and related COM data, it becomes possible
                        to identify signals that distinguish the two cases.
                    </div>
                    <div className="pt-2">
                        The important takeaway is not a single static rule. It is the
                        research process: select a relevant provider, collect benign and
                        suspicious samples, compare the fields that change, and then validate
                        the resulting detection against more real-world activity.
                    </div>

                    <SecondaryHeader text="Get Started" />
                    <div className="pt-4">
                        If you want to follow along, download EtwSuite from the{' '}
                        <StyledLink
                            href="https://github.com/Idov31/EtwSuite"
                            content="project repository"
                            textSize="text-md"
                        />{' '}
                        and use the video as a starting point for exploring the providers on
                        your own system.
                    </div>
                </article>
            </div>
        </div>
    );
}
