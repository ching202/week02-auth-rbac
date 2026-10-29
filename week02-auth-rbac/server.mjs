import { readConfig } from './src/config.mjs';
import { createApplication } from './src/app.mjs';

try {
  const config = readConfig();
  const app = await createApplication(config);
  await app.listen(config.port, config.host);
  console.log(`Gatehouse is running at ${config.origin}`);
  console.log('Press Ctrl+C to stop.');
  let closing = false;
  for (const signal of ['SIGINT', 'SIGTERM']) {
    process.on(signal, async () => {
      if (closing) return;
      closing = true;
      await app.close();
      process.exit(0);
    });
  }
} catch (error) {
  console.error(`Startup failed: ${error.message}`);
  process.exitCode = 1;
}
