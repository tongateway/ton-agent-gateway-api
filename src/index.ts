import { buildServer } from './server';
import { config } from './config';

async function main() {
  const app = await buildServer();

  try {
    await app.listen({
      host: config.HOST,
      port: config.PORT,
    });
  } catch (error) {
    app.log.error(error);
    process.exit(1);
  }
}

void main();
