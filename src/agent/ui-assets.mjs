// Explicit assets, not a filesystem route. User-provided paths never select files.
const ui = (name, type) => [new URL('./ui/' + name, import.meta.url), type];
const assets = new Map([
  ['/folders', ui('folders.html', 'text/html')],
  ['/folders.js', ui('folders.js', 'text/javascript')],
  ['/folders.css', ui('folders.css', 'text/css')],
  ['/lifecycle.js', ui('lifecycle.js', 'text/javascript')],
  ['/installation.js', [new URL('../shared/installation.mjs', import.meta.url), 'text/javascript']],

  // Compatibility and authorization flows. Normal launchers open /folders.
  ['/', ui('connect.html', 'text/html')],
  ['/connect.js', ui('connect.js', 'text/javascript')],
  ['/connect.css', ui('connect.css', 'text/css')],
  ['/manage', ui('home.html', 'text/html')],
  ['/developer', ui('index.html', 'text/html')],
  ['/home.js', ui('home.js', 'text/javascript')],
  ['/home.css', ui('home.css', 'text/css')],
  ['/app.js', ui('app.js', 'text/javascript')],
  ['/style.css', ui('style.css', 'text/css')],
  ['/onboarding.js', ui('onboarding.js', 'text/javascript')],
  ['/self-host.html', ui('self-host.html', 'text/html')],
]);

export function uiAsset(route) {
  return assets.get(route);
}
