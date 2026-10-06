// Browser acceptance helper: uses actual local folder-browse HTTP endpoints,
// not a stubbed Windows picker or filesystem-handle mock.
export async function chooseFolder(page, folder, { mode } = {}) {
  await page.locator('#chooseFolder').click();
  await page.locator('#browsePath').fill(folder);
  await page.locator('#browseGo').click();
  await page.waitForFunction(expected => document.querySelector('#browsePath').value === expected && !document.querySelector('#useFolder').disabled, folder, { timeout: 6000 }).catch(async error => { throw new Error(`${error.message}; chooser=${JSON.stringify(await page.evaluate(() => ({ path: document.querySelector('#browsePath').value, note: document.querySelector('#browseNote').textContent, entries: document.querySelector('#browseEntries').textContent })))}`); });
  if (mode) {
    await page.locator('#newFolderOptions > summary').click();
    await page.locator('#newFolderMode').selectOption(mode);
  }
  await page.locator('#useFolder').click();
  await page.waitForFunction(() => document.querySelector('#pickerNotice').hidden === true && document.querySelector('#folders .folder'));
}
