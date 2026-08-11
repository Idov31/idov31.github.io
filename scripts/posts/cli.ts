import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { checkDraft, publishDraft } from './publisher';

function usage(): void {
    console.error('Usage: tsx scripts/posts/cli.ts <check|publish> <drafts/post.md>');
}

export async function runCli(args: string[]): Promise<number> {
    const [command, input, ...extra] = args;
    if ((command !== 'check' && command !== 'publish') || !input || extra.length > 0) {
        usage();
        return 2;
    }

    const result = command === 'check' ? await checkDraft(input) : await publishDraft(input);
    if (result.diagnostics.length > 0) {
        for (const entry of result.diagnostics) {
            console.error(`${entry.source ? `${entry.source}: ` : ''}${entry.message}`);
        }
        return 1;
    }

    console.log(command === 'check' ? `Validated ${input}.` : `Published ${input}.`);
    return 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    runCli(process.argv.slice(2)).then((exitCode) => {
        process.exitCode = exitCode;
    }).catch((error: unknown) => {
        console.error(error instanceof Error ? error.message : 'Unexpected post publishing error.');
        process.exitCode = 1;
    });
}
