import assert from 'node:assert/strict';

// Each caller-supplied step observes its own bound and records failure instead
// of stopping later steps. Server close must run even if client close stalls.
export async function closeBrowserFixture(browser, server, state, cleanup) {
  await cleanup('browser-contexts', () => browser && Promise.all(browser.contexts().map(context => context.close())), 8000);
  await cleanup('browser-client', () => browser?.close(), 8000);
  await cleanup('browser-server', () => server?.close(), 35000);
  await cleanup('browser-drain', () => {
    if (server) assert.ok(state.exitObserved && state.closeObserved && state.stdoutEnded && state.stderrEnded, 'Owned browser process and pipe drain were not confirmed.');
  }, 1000);
}
