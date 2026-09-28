import { test } from 'node:test'
import assert from 'node:assert/strict'
import { prepareUpload, droppedFiles } from './uploads.ts'

test('individual files keep their original bytes', async () => {
  const file = new File(['SHA256'], 'hash.py')
  assert.equal(prepareUpload([{ file, path: file.name }]), file)
})

test('folder archives preserve nested Unicode and long paths with PAX headers', async () => {
  const path = 'demo/nested/' + 'long'.repeat(40) + '/clé.py'
  const file = new File(['MD5'], 'clé.py')
  const archive = prepareUpload([{ file, path }])
  assert.equal(archive.name, 'demo.tar')
  const bytes = new Uint8Array(await archive.arrayBuffer())
  const size = parseInt(new TextDecoder().decode(bytes.slice(124, 135)), 8)
  const pax = new TextDecoder().decode(bytes.slice(512, 512 + size))
  assert.equal(Number(pax.split(' ')[0]), size)
  assert.ok(pax.includes(`path=${path}\n`))
  assert.equal(archive.size % 512, 0)
  assert.ok(new TextDecoder().decode(bytes).includes('MD5'))
})

test('empty folders and oversized inputs report useful errors', () => {
  assert.throws(() => prepareUpload([]), /empty/)
  assert.throws(() => prepareUpload([{ file: { name: 'big', size: 129 * 1024 * 1024 }, path: 'big' }]), /128 MiB/)
})

test('dropped folders read every browser batch and retain hierarchy', async () => {
  const entry = name => ({ name, isFile: true, isDirectory: false, file: resolve => resolve(new File(['AES'], name)) })
  const batches = [[entry('one.py')], [entry('two.py')], []]
  const folder = { name: 'demo', isDirectory: true, isFile: false, createReader: () => ({ readEntries: resolve => resolve(batches.shift()) }) }
  const files = await droppedFiles([{ kind: 'file', webkitGetAsEntry: () => folder }], [])
  assert.deepEqual(files.map(item => item.path), ['demo/one.py', 'demo/two.py'])
})
