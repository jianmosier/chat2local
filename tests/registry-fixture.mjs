import { readArtifact } from './relay-runtime.mjs';
import { RustRegistryRunner } from '../src/relay/rust-registry.mjs';
import { AccountDirectory as OriginalAccountDirectory } from '../src/relay/account-directory.mjs';
import { OnboardingStore as OriginalOnboardingStore } from '../src/relay/onboarding-store.mjs';
import { PrivateInstance as OriginalPrivateInstance } from '../src/relay/private-instance.mjs';
import { InstallPortal as OriginalInstallPortal } from '../src/relay/install-portal.mjs';
export { invitationParts } from '../src/relay/private-instance.mjs';
const directory=process.env.CHAT2LOCAL_OAUTH_TEST_ARTIFACT_DIR??process.env.CHAT2LOCAL_REGISTRY_TEST_ARTIFACT_DIR;
if(process.env.CHAT2LOCAL_REGISTRY_TEST_REQUIRED==='1'&&!directory)throw Error('Strict aggregate tests require a Registry artifact directory.');
const compiled=directory?new WebAssembly.Module((await readArtifact(directory)).registryBytes):null;
const selected=()=>compiled?new RustRegistryRunner(compiled):undefined;
export class AccountDirectory extends OriginalAccountDirectory { constructor(storage,options={}){super(storage,{runner:selected(),...options});} }
export class OnboardingStore extends OriginalOnboardingStore { constructor(storage,now,runner=selected()){super(storage,now,runner);} }
export class PrivateInstance extends OriginalPrivateInstance { constructor(storage,resource,now,runner=selected()){super(storage,resource,now,runner);} }
export class InstallPortal extends OriginalInstallPortal { constructor(storage,resource,pepper,now,runner=selected()){super(storage,resource,pepper,now,runner);} }
