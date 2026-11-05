import { optionsFor, buildTransport, buildEnvironment, run } from './build-rust-transport.mjs';
const options = optionsFor(process.argv.slice(2));
await run('cargo', ['test', '--locked', '-p', 'chat2local-agent-transport', '-p', 'chat2local-agent-transport-fixture', '--target-dir', options.target], await buildEnvironment(options));
const artifact = await buildTransport(options);
await run(process.execPath, ['--test', '--test-concurrency=1', 'tests/rust-transport.test.mjs'], { ...process.env, CHAT2LOCAL_TRANSPORT_TEST_REQUIRED: '1', CHAT2LOCAL_TRANSPORT_TEST_EXECUTABLE: artifact.executable });
