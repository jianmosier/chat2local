// Explicit provider profile. The existing bearer builder remains the v1 gate.
process.argv.push('--profile','provider');
await import('./build-rust-oauth.mjs');
