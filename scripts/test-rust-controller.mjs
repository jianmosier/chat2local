import { run } from './build-rust-transport.mjs';
import { readTransportArtifact } from './transport-artifact.mjs';
import { readControllerArtifact } from './controller-artifact.mjs';
const executable = process.env.CHAT2LOCAL_CONTROLLER_TEST_EXECUTABLE;
if (!executable) throw Error('Explicit fresh controller fixture executable required.');
await readControllerArtifact(executable);
if (!process.env.CHAT2LOCAL_TRANSPORT_TEST_EXECUTABLE) throw Error('Explicit fresh transport fixture executable required for synthetic TLS.');
await readTransportArtifact(process.env.CHAT2LOCAL_TRANSPORT_TEST_EXECUTABLE);
await run(process.execPath, ['--test', 'tests/rust-controller.test.mjs', 'tests/controller-ownership.test.mjs', 'tests/rust-bridge.test.mjs'], { ...process.env, CHAT2LOCAL_CONTROLLER_TEST_REQUIRED: '1' });
