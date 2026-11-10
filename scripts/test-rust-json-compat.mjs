import { buildJsonCompat, optionsFor, run } from './build-rust-json-compat.mjs';
const options=optionsFor(process.argv.slice(2)),artifacts=await buildJsonCompat(options);
run('cargo',['test','--locked','-p','chat2local-js-value-compat','-p','chat2local-js-value-compat-fixture','--target-dir',options.target]);
run(process.execPath,['--test','--test-concurrency=1','tests/rust-json-compat.test.mjs'],{...process.env,CHAT2LOCAL_JSON_COMPAT_TEST_REQUIRED:'1',CHAT2LOCAL_JSON_COMPAT_TEST_EXECUTABLE:artifacts.executable,CHAT2LOCAL_JSON_COMPAT_TEST_WASM:artifacts.wasm});
