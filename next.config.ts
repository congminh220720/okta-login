import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  cacheComponents: false,
  turbopack: { root: process.cwd() },
};

export default nextConfig;
