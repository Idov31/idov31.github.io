import { blogPosts } from '@/data/blogPosts';

export const dynamic = 'force-static';

const siteUrl = 'https://idov31.github.io';
const channelTitle = 'Ido Veltzman :: Security Research';
const channelDescription = 'Security research and technical articles by Ido Veltzman.';

function escapeXml(value: string): string {
    return value
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/'/g, '&apos;')
        .replace(/"/g, '&quot;');
}

function toRfc822Date(date: string): string {
    return new Date(`${date} UTC`).toUTCString();
}

export function GET(): Response {
    const items = blogPosts.map((post) => {
        const url = `${siteUrl}${post.href}`;
        const publishedAt = toRfc822Date(post.subHeaderContent);

        return `    <item>
      <title>${escapeXml(post.headerContent)}</title>
      <link>${escapeXml(url)}</link>
      <guid isPermaLink="true">${escapeXml(url)}</guid>
      <description>${escapeXml(post.postContent)}</description>
      <pubDate>${publishedAt}</pubDate>
    </item>`;
    }).join('\n');

    const rss = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>${channelTitle}</title>
    <link>${siteUrl}</link>
    <description>${channelDescription}</description>
    <language>en</language>
    <lastBuildDate>${toRfc822Date(blogPosts[0].subHeaderContent)}</lastBuildDate>
${items}
  </channel>
</rss>`;

    return new Response(rss, {
        headers: {
            'Content-Type': 'application/rss+xml; charset=utf-8',
        },
    });
}
