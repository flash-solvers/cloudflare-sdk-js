// Solve a Cloudflare challenge and print the cf_clearance cookie.
//
//   FLASH_API_KEY=... node examples/solve.js https://example.com/

const { CloudflareSolver } = require('..');

async function main() {
  const solver = new CloudflareSolver({
    apiKey: process.env.FLASH_API_KEY,
    proxy: process.env.PROXY,
    endpoint: process.env.FLASH_ENDPOINT || undefined,
  });
  const result = await solver.solve(process.argv[2]);
  console.log(`cf_clearance=${result.clearance}\nattempts=${result.attempts}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
