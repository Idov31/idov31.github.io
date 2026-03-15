---
title: "Writing Blog Posts in Markdown"
date: "15.03.2026"
description: "A quick guide showing how to write blog posts in Markdown for this site — with full support for code blocks, images, lists, tables and more."
projectLink: "https://github.com/Idov31/idov31.github.io"
imagePath: "/post-images/function-stomping.png"
imageAlt: "markdown-guide"
imageWidth: 135
imageHeight: 51
tags: ["markdown", "guide", "blogging"]
---

## Introduction

Blog posts on this site can now be written in plain **Markdown** instead of hand-crafted TSX.
Drop a `.md` file into `src/content/posts/` and the site automatically renders it with the
same design and style as the existing posts — no code changes required.

Add the post to `src/data/blogPosts.ts` so it appears in the listing page.

---

## Frontmatter reference

Every post starts with a YAML frontmatter block:

```yaml
---
title: "Your Post Title"
date: "DD.MM.YYYY"
description: "Short summary shown in the post listing."
projectLink: "https://github.com/..."   # optional — omit if no linked repo
imagePath: "/post-images/your-image.png"
imageAlt: "alt text"
imageWidth: 135
imageHeight: 51
tags: ["tag1", "tag2"]
---
```

`projectLink` is optional. When provided, GitHub star / fork / follow buttons are
shown below the post title.

---

## Text formatting

Regular paragraph text uses the site's `text-txtRegular` colour in both light and dark mode.

You can use **bold**, _italic_, and `inline code` inline.

> Blockquotes are styled with a purple left border and muted italic text.

---

## Code blocks

Fenced code blocks are rendered with syntax highlighting (Dracula theme) and line numbers.
Specify the language after the opening fence:

```cpp
#include <windows.h>

int main() {
    MessageBoxW(nullptr, L"Hello from Markdown!", L"Demo", MB_OK);
    return 0;
}
```

```rust
fn main() {
    println!("Hello from Rust!");
}
```

> **Note:** The collapsible "Expand / Collapse" code block feature available in TSX posts
> is *not* supported in Markdown. All code is shown in full.

---

## Lists

Unordered lists use the purple arrow bullet (▸):

- First item
- Second item
- Third item with `inline code`

Ordered lists:

1. Clone the repository
2. Add your `.md` file to `src/content/posts/`
3. Register the post in `src/data/blogPosts.ts`
4. Run `npm run dev` to preview

---

## Images

Images are rendered using the `BlogImageFigure` component. The alt text is reused as the
caption:

![Example image caption](/post-images/function-stomping/shellcode_injection.png)

---

## Links

External links open in a new tab automatically:
[GitHub repository](https://github.com/Idov31/idov31.github.io)

Internal links navigate within the SPA:
[Back to all posts](/posts)

---

## Tables

Tables are styled with the site's border and surface colours:

| Feature | TSX posts | Markdown posts |
|---|---|---|
| Syntax highlighting | ✅ | ✅ |
| Table of contents | ✅ | ✅ |
| Images | ✅ | ✅ |
| Inline code | ✅ | ✅ |
| Expandable code blocks | ✅ | ❌ |
| Full-text search | ✅ | ✅ |

---

## Limitations

The following features from the hand-crafted TSX posts **cannot** be expressed in plain
Markdown and are therefore not available when writing in Markdown:

- **Expandable / collapsible code blocks** — the `isMessageToggled` prop on the `Code`
  component requires explicit JSX. All code blocks are shown in full.
- **RoadmapTimeline** — there is no Markdown equivalent for the timeline visualisation
  component; it is not used in blog posts anyway.

If you need either of these features, write the post as a TSX component in its own folder
under `src/app/posts/` (the existing approach).
