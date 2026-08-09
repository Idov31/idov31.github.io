'use client';

import type React from 'react';
import Script from 'next/script';

declare global {
    namespace JSX {
        interface IntrinsicElements {
            'wistia-player': React.DetailedHTMLProps<React.HTMLAttributes<HTMLElement>, HTMLElement> & {
                'media-id': string;
                aspect?: string;
            };
        }
    }
}

export interface WistiaVideoProps {
    mediaId: string;
    title: string;
    aspectRatio?: string;
}

export default function WistiaVideo({
    mediaId,
    title,
    aspectRatio = '1.7777777777777777',
}: WistiaVideoProps) {
    const swatchUrl = `https://fast.wistia.com/embed/medias/${mediaId}/swatch`;

    return (
        <div
            className="relative aspect-video overflow-hidden rounded-xl border border-borderSubtle bg-bgSurface"
            style={{
                backgroundImage: `url('${swatchUrl}')`,
                backgroundPosition: 'center',
                backgroundRepeat: 'no-repeat',
                backgroundSize: 'cover',
            }}
        >
            <Script src="https://fast.wistia.com/player.js" strategy="afterInteractive" />
            <Script
                src={`https://fast.wistia.com/embed/${mediaId}.js`}
                strategy="afterInteractive"
                type="module"
            />
            <wistia-player
                media-id={mediaId}
                aspect={aspectRatio}
                aria-label={title}
                className="absolute inset-0 block h-full w-full"
            />
        </div>
    );
}
