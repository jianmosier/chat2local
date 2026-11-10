import path from 'node:path';
import { optionsFor,buildNativeStore,run } from './build-rust-native-store.mjs';
import { buildJsonCompat } from './build-rust-json-compat.mjs';
const options=optionsFor(process.argv.slice(2));
if(process.platform!=='win32')throw Error('Strict N1 requires actual Windows DPAPI.');
run('cargo',['test','--locked','-p','chat2local-native-store','-p','chat2local-native-store-fixture','--target-dir',options.target]);
const native=await buildNativeStore(options),json=await buildJsonCompat({target:options.target,output:path.join(options.output,'json-compat')});
run(process.execPath,['--test','--test-concurrency=1','tests/rust-native-store.test.mjs','tests/rust-json-compat.test.mjs'],{...process.env,CHAT2LOCAL_NATIVE_STORE_TEST_REQUIRED:'1',CHAT2LOCAL_NATIVE_STORE_TEST_EXECUTABLE:native.executable,CHAT2LOCAL_JSON_COMPAT_TEST_REQUIRED:'1',CHAT2LOCAL_JSON_COMPAT_TEST_EXECUTABLE:json.executable,CHAT2LOCAL_JSON_COMPAT_TEST_WASM:json.wasm});
