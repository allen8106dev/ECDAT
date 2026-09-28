import { test } from 'node:test'
import assert from 'node:assert/strict'
import { summarize } from './insights.ts'

test('heatmap preserves repeated evidence and distinct file links', () => {
  const summary = summarize([
    { file: 'a.py', pattern: 'RSA', severity: 'HIGH' },
    { file: 'a.py', pattern: 'RSA', severity: 'high' },
    { file: 'b.c', pattern: 'RSA', severity: 'review' },
    { file: 'a.py', pattern: 'AES', severity: 'unexpected' },
  ])
  assert.equal(summary[0].name, 'RSA')
  assert.equal(summary[0].total, 3)
  assert.deepEqual(summary[0].counts, [2, 1, 0, 0])
  assert.deepEqual([...summary[0].files], [['a.py', 2], ['b.c', 1]])
  assert.equal(summary[1].counts[3], 1)
})

test('empty and maximum-sized finding sets retain correct totals', () => {
  assert.deepEqual(summarize([]), [])
  const rows = Array.from({ length: 20000 }, (_, i) => ({ file: `file${i}`, pattern: 'SHA256', severity: 'low' }))
  const [asset] = summarize(rows)
  assert.equal(asset.total, 20000)
  assert.equal(asset.files.size, 20000)
})
