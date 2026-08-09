export interface PostFrontmatter {
    formatVersion: 1;
    slug: string;
    title: string;
    date: string;
    projectLink: string;
    summary: string;
    cardImage: string;
    cardImageAlt: string;
    cardImageWidth: number;
    cardImageHeight: number;
    sub: boolean;
}

export interface PostDiagnostic {
    message: string;
    line: number;
    column: number;
    code:
        | 'frontmatter'
        | 'validation'
        | 'unsupported'
        | 'syntax';
}

export interface CompilePostResult {
    frontmatter?: PostFrontmatter;
    generatedTsx?: string;
    diagnostics: PostDiagnostic[];
}

export interface RoadmapItem {
    version: string;
    description: string;
    features?: string[];
    bugfixes?: string[];
    isCurrentRelease?: boolean;
    isCompleted?: boolean;
}

export interface RoadmapData {
    title?: string;
    description?: string;
    items: RoadmapItem[];
}
