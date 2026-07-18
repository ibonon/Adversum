/** @type {import('next').NextConfig} */
const nextConfig = {
    swcMinify: true,
    webpack: (config) => {
        // Fix for "Unable to snapshot resolve dependencies" on Windows
        config.snapshot = {
            ...(config.snapshot || {}),
            managedPaths: [],
        };
        return config;
    },
};

export default nextConfig;
