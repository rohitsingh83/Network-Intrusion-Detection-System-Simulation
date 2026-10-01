import type { NextConfig } from 'next';

/**
 * next.config.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Static export configuration for GitHub Pages deployment.
 *
 * GitHub Pages URL:
 *   https://rohitsingh83.github.io/Network-Intrusion-Detection-System-Simulation/
 *
 * For local dev / FastAPI serving, basePath is empty.
 * The GITHUB_PAGES env var is set to "true" by the GitHub Actions workflow.
 */

const isGithubPages = process.env.GITHUB_PAGES === 'true';
const repoName = 'Network-Intrusion-Detection-System-Simulation';

const nextConfig: NextConfig = {
  output: 'export',
  trailingSlash: true,
  images: { unoptimized: true },

  // Only set basePath when building for GitHub Pages
  ...(isGithubPages && {
    basePath:  `/${repoName}`,
    assetPrefix: `/${repoName}/`,
  }),

  // Inject NEXT_PUBLIC_STANDALONE=true when building for GH Pages
  // so the app auto-switches to mock-engine mode at runtime
  env: {
    NEXT_PUBLIC_STANDALONE: isGithubPages ? 'true' : 'false',
  },
};

export default nextConfig;
