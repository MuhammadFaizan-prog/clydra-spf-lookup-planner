import type { DnsAnswer, RRType, Resolver } from "./spf";

// DNS-over-HTTPS JSON APIs that allow browser (CORS) requests.
export const PROVIDERS = {
  google: { label: "Google Public DNS", url: (n: string, t: RRType) => `https://dns.google/resolve?name=${encodeURIComponent(n)}&type=${t}` },
  cloudflare: { label: "Cloudflare 1.1.1.1", url: (n: string, t: RRType) => `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(n)}&type=${t}` },
} as const;

export type ProviderId = keyof typeof PROVIDERS;

const TYPE_CODE: Record<RRType, number> = { A: 1, MX: 15, TXT: 16, AAAA: 28 };

interface DohJson {
  Status: number;
  Answer?: { name: string; type: number; data: string }[];
}

export function dohResolver(provider: ProviderId, timeoutMs = 6000, fetchImpl: typeof fetch = fetch): Resolver {
  return async (name: string, type: RRType): Promise<DnsAnswer> => {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const res = await fetchImpl(PROVIDERS[provider].url(name, type), { headers: { accept: "application/dns-json" }, signal: ctrl.signal });
      if (!res.ok) return { status: "error", records: [], error: `HTTP ${res.status} from ${PROVIDERS[provider].label}` };
      const json = (await res.json()) as DohJson;
      if (json.Status === 3) return { status: "nxdomain", records: [] };
      if (json.Status !== 0) return { status: "error", records: [], error: `DNS status ${json.Status} (SERVFAIL or refused)` };
      const records = (json.Answer ?? []).filter((a) => a.type === TYPE_CODE[type]).map((a) => a.data);
      return { status: records.length ? "ok" : "nodata", records };
    } catch (e) {
      const aborted = e instanceof DOMException && e.name === "AbortError";
      return { status: "error", records: [], error: aborted ? `timed out after ${timeoutMs / 1000}s` : "network error (offline or blocked)" };
    } finally {
      clearTimeout(timer);
    }
  };
}
