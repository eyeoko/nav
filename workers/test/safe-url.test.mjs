import assert from 'node:assert/strict';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { createBackend } from './helpers.mjs';

let safeUrlModule;
function loadSafeUrl() {
  safeUrlModule ??= build({
    stdin: {
      contents: "export { sanitizeHttpUrl, sanitizeSiteUrl } from './workers/src/safe-url.ts';",
      resolveDir: fileURLToPath(new URL('../../', import.meta.url)),
      loader: 'ts',
    },
    bundle: true,
    write: false,
    format: 'esm',
    platform: 'browser',
    target: 'es2022',
  }).then(async ({ outputFiles }) => {
    const code = outputFiles[0].text;
    return import('data:text/javascript;base64,' + Buffer.from(code).toString('base64'));
  });
  return safeUrlModule;
}

const UNSAFE_URLS = [
  'chrome://contextual-tasks/?q=1',
  'chrome://settings/importData',
  'javascript:alert(1)',
  'javascript:void (function(d) {var e = d.createElement("script");e.src = "x";}(document));',
  'JavaScript:alert(1)',
  ' java\tscript:alert(1)',
  'vbscript:msgbox(1)',
  'data:text/html,<script>alert(1)</script>',
  'file:///etc/passwd',
  'blob:https://example.com/11111111-1111-1111-1111-111111111111',
  '//evil.example.com/x',
];

test('sanitizeHttpUrl：仅绝对 HTTP(S) 通过，浏览器内部页与脚本链接全部拒绝', async () => {
  const { sanitizeHttpUrl } = await loadSafeUrl();
  assert.equal(sanitizeHttpUrl('https://example.com/'), 'https://example.com/');
  assert.equal(
    sanitizeHttpUrl('http://example.com:8080/path?q=1#top'),
    'http://example.com:8080/path?q=1#top'
  );
  assert.equal(sanitizeHttpUrl('  https://example.com/  '), 'https://example.com/');
  for (const url of UNSAFE_URLS) {
    assert.equal(sanitizeHttpUrl(url), null, url);
  }
  assert.equal(sanitizeHttpUrl(null), null);
  assert.equal(sanitizeHttpUrl(42), null);
});

test('sanitizeSiteUrl：默认白名单放行 mailto/tel 与相对链接，危险 scheme 拒绝', async () => {
  const { sanitizeSiteUrl } = await loadSafeUrl();
  assert.equal(sanitizeSiteUrl('https://example.com/'), 'https://example.com/');
  assert.equal(sanitizeSiteUrl('mailto:sun@example.com'), 'mailto:sun@example.com');
  assert.equal(sanitizeSiteUrl('tel:+8613800138000'), 'tel:+8613800138000');
  assert.equal(sanitizeSiteUrl('./relative/page'), './relative/page');
  assert.equal(sanitizeSiteUrl('#anchor'), '#anchor');
  for (const url of UNSAFE_URLS) {
    assert.equal(sanitizeSiteUrl(url), null, url);
  }
});

test('POST /api/seed：夹带 chrome://javascript: 链接整体 400，不覆盖已有内容（CI 快照契约回归）', async (t) => {
  const app = await createBackend();
  t.after(() => app.dispose());
  const ok = await app.request('POST', '/api/seed', {
    pages: [
      {
        id: 'home',
        label: '首页',
        categories: [
          {
            label: '工具',
            sites: [{ name: 'GitHub', url: 'https://github.com/' }],
          },
        ],
      },
    ],
  });
  assert.equal(ok.status, 200, JSON.stringify(ok.data));
  for (const url of ['chrome://settings/importData', 'javascript:alert(1)']) {
    const rejected = await app.request('POST', '/api/seed?reset=1', {
      pages: [
        {
          id: 'home',
          label: '首页',
          categories: [{ label: '工具', sites: [{ name: '坏链接', url }] }],
        },
      ],
    });
    assert.equal(rejected.status, 400, JSON.stringify(rejected.data));
    assert.equal(rejected.data.detail, '站点链接无效或使用不安全的协议');
  }
  const state = await app.request('GET', '/api/state');
  assert.equal(state.data[0].categories[0].sites.length, 1);
  assert.equal(state.data[0].categories[0].sites[0].name, 'GitHub');
  assert.equal(state.data[0].categories[0].sites[0].url, 'https://github.com/');
});
