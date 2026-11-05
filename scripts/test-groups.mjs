// Keep the slow browser suite bounded independently of unrelated test files.
// Every remaining file still runs, serially, across the other five groups.
export const TEST_GROUPS = 6;
export function testGroupFiles(files, group) {
  if (!Number.isInteger(group) || group < 1 || group > TEST_GROUPS) throw Error('Invalid test group.');
  if (!Array.isArray(files) || new Set(files).size !== files.length || !files.includes('folders-ui.test.mjs')) throw Error('Incomplete or duplicate test inventory.');
  const sorted = [...files].sort();
  if (group === 1) return ['folders-ui.test.mjs'];
  return sorted.filter(name => name !== 'folders-ui.test.mjs').filter((_name, index) => index % (TEST_GROUPS - 1) === group - 2);
}
