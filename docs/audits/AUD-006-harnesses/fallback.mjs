import { readFile } from 'node:fs/promises';
import assert from 'node:assert/strict';

const binary = await readFile(process.argv[2]);
const { instance } = await WebAssembly.instantiate(binary);
for (const name of ['check_buffer', 'check_closed', 'check_work_area', 'check_strict']) {
  assert.equal(instance.exports[name](), 1, name);
  console.log(name + ' passed');
}
