import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const html = await readFile(new URL("../index.html", import.meta.url), "utf8");
const css = await readFile(new URL("../styles.css", import.meta.url), "utf8");

assert.match(html, /name="viewport"[^>]*width=device-width/);
assert.match(html, /id="main-content"/);
for (const id of ["connection", "streams", "chunk-reader", "spatial-tools"]) {
  assert.match(html, new RegExp('id="' + id + '"'));
}
for (const id of [
  "connect-form", "gateway-url", "gateway-token", "disconnect-button",
  "stream-list", "chunk-form", "chunk-list", "mmo-form", "mmo-simplify-form",
  "mmo-resolve-form", "mmo-entity-list", "mmo-simplify-list"
]) {
  assert.match(html, new RegExp('id="' + id + '"'), "missing application hook: " + id);
}
assert.match(css, /grid-template-columns:\s*minmax\(0,\s*1fr\)/);
assert.match(css, /@media\s*\(min-width:\s*42rem\)/);
assert.match(css, /@media\s*\(min-width:\s*64rem\)/);
assert.match(css, /@media\s*\(min-width:\s*100rem\)/);
assert.match(css, /@media\s*\(min-width:\s*140rem\)/);
assert.match(css, /repeat\(auto-fit,\s*minmax/);
assert.match(css, /clamp\(/);
assert.match(css, /prefers-reduced-motion/);
assert.match(css, /forced-colors/);
assert.match(css, /pointer:\s*coarse/);
assert.doesNotMatch(css, /\.shell\s*\{[^}]*width:\s*980px/s);
console.log("Responsive browser-WASM layout contract passed.");
