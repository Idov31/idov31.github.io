# Markdown Post Publisher

Draft posts are local Markdown files beneath `drafts/` and are intentionally ignored by Git. A successful publication keeps the draft, fully regenerates `src/app/posts/<slug>/page.tsx`, and creates or replaces the corresponding entry in `src/data/blogPosts.ts`.

Validate a draft without writing files:

```powershell
npm run post:check -- drafts/my-post.md
```

Publish it:

```powershell
npm run post:publish -- drafts/my-post.md
```

`post:publish` deliberately replaces the complete generated page for its slug. Do not manually edit a generated page if you intend to publish that draft again.

## Frontmatter

Every draft starts with this YAML mapping. `cardImageWidth`, `cardImageHeight`, and `sub` are optional and default to `135`, `51`, and `false`.

```yaml
---
formatVersion: 1
slug: my-post
title: "My Post"
date: "2026-05-02"
projectLink: "https://github.com/Idov31/example"
summary: "The post summary used for listings, search, and RSS."
cardImage: "/post-images/my-post/card.png"
cardImageAlt: "My post"
---
```

The slug must be lowercase and hyphenated. Dates are ISO calendar dates. Project links are HTTP(S), and every image path must be root-relative under `/post-images/` and already exist in `public/post-images/`.

## Supported body syntax

- `##` and `###` generate the existing post section headers. The title comes from frontmatter; other heading levels are rejected.
- Normal paragraphs, bold, italic, strikethrough, hard breaks, inline code, HTTP(S)/`mailto:`/internal links, flat ordered lists, and flat unordered lists are supported.
- Fenced code uses its language name. Add `collapsible message="Show code"` after the language to generate the existing expandable code block.
- A standalone Markdown image generates `BlogImageFigure`; its optional Markdown title becomes the caption.
- Use `::image{src="..." alt="..." caption="..." sourceHref="..."}` for a figure with an explicit source link.
- Use `:::lead` around opening prose for the site’s drop-cap styling.
- Use `:::roadmap` containing exactly one fenced YAML object with `title`, optional `description`, and an `items` array. Each item needs `version` and `description`; optional `features`, `bugfixes`, `isCompleted`, and `isCurrentRelease` map to `RoadmapTimeline`.

Raw HTML/JSX, tables, blockquotes, task lists, nested lists, thematic breaks, unknown directives, and unsupported YAML fields fail validation instead of being passed through.
