import { defineConfig, type Plugin } from "vitest/config";

// Production builds ship a strict Content-Security-Policy. Network access is limited to the two DNS-over-HTTPS resolvers.
const CSP = "default-src 'self'; img-src 'self' data:; style-src 'self'; object-src 'none'; base-uri 'self'; form-action 'none'; connect-src https://dns.google https://cloudflare-dns.com";

function cspMeta(): Plugin {
  return {
    name: "clydara-csp-meta",
    apply: "build",
    transformIndexHtml(html) {
      return html.replace("<head>", `<head>\n    <meta http-equiv="Content-Security-Policy" content="${CSP}" />`);
    },
  };
}

export default defineConfig({
  plugins: [cspMeta()],
  build: {
    target: "es2022",
    sourcemap: false,
    rollupOptions: { input: { index: "index.html", tool: "tool.html" } },
  },
  test: { environment: "node", include: ["tests/**/*.test.ts"] },
});
