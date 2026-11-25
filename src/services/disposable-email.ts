let domains: Set<string> | null = null;

async function loadDomains(): Promise<Set<string>> {
    if (domains) return domains;

    const source = await Deno.readTextFile(new URL("../data/disposable_domains.txt", import.meta.url));

    domains = new Set(
        source
            .split("\n")
            .map(line => line.trim().toLowerCase())
            .filter(line => line.length > 0 && !line.startsWith("#")),
    );

    return domains;
}

// matches a domain or any parent domain in the blocklist
export async function isDisposableEmail(email: string): Promise<boolean> {
    const at = email.lastIndexOf("@");
    if (at === -1) return false;

    const domain = email.slice(at + 1).trim().toLowerCase();
    if (!domain) return false;

    const list = await loadDomains();
    if (list.has(domain)) return true;

    const parts = domain.split(".");
    for (let i = 1; i < parts.length - 1; i++) {
        if (list.has(parts.slice(i).join("."))) return true;
    }

    return false;
}
