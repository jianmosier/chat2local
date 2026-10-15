import { VERSION } from './protocol.mjs';

// Repository ownership belongs to distribution configuration, not user commands.
// Standalone install.sh / install.ps1 mirror this value; tests enforce agreement.
export const SOURCE_REPOSITORY = 'jianmosier/chat2local';

export function bootstrapSource(extension, version = VERSION) {
  if (!['sh', 'ps1'].includes(extension) || !/^0\.1\.0-alpha\.\d+$/.test(version)) {
    throw new Error('A supported, version-pinned bootstrap is required.');
  }
  return `https://raw.githubusercontent.com/${SOURCE_REPOSITORY}/v${version}/install.${extension}`;
}
