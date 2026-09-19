import type { ReactNode } from 'react';

export type BlogTableAlignment = 'left' | 'center' | 'right' | null;

export interface BlogTableProps {
    headers: ReactNode[];
    rows: ReactNode[][];
    alignments?: BlogTableAlignment[];
    caption?: string;
}

const alignmentClasses: Record<Exclude<BlogTableAlignment, null>, string> = {
    left: 'text-left',
    center: 'text-center',
    right: 'text-right',
};

function alignmentClass(alignment: BlogTableAlignment | undefined): string {
    return alignment ? alignmentClasses[alignment] : 'text-left';
}

export default function BlogTable({ headers, rows, alignments, caption }: BlogTableProps) {
    return (
        <div className="pt-4 pb-2">
            <div
                className="overflow-x-auto rounded-xl border border-borderSubtle bg-bgInsideDiv"
                tabIndex={0}
                aria-label={caption ? `${caption} table` : 'Scrollable table'}
            >
                <table className="min-w-full border-collapse text-left text-sm text-txtRegular md:text-base">
                    {caption && (
                        <caption className="caption-bottom px-4 pt-3 text-center text-sm italic text-txtSubHeader">
                            {caption}
                        </caption>
                    )}
                    <thead className="border-b border-borderMid bg-bgSemiTransparent text-txtHeader">
                        <tr>
                            {headers.map((header, index) => (
                                <th
                                    key={index}
                                    scope="col"
                                    className={`whitespace-nowrap px-4 py-3 font-semibold ${alignmentClass(alignments?.[index])}`}
                                >
                                    {header}
                                </th>
                            ))}
                        </tr>
                    </thead>
                    <tbody>
                        {rows.map((row, rowIndex) => (
                            <tr key={rowIndex} className="border-b border-borderSubtle last:border-b-0 even:bg-bgSemiTransparent">
                                {row.map((cell, cellIndex) => (
                                    <td
                                        key={cellIndex}
                                        className={`px-4 py-3 align-top ${alignmentClass(alignments?.[cellIndex])}`}
                                    >
                                        {cell}
                                    </td>
                                ))}
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
}
