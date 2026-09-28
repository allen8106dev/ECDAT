export type Evidence = { file: string; pattern: string; severity: string }
export const priorities = ['high', 'review', 'info', 'unknown']
export function summarize(findings: Evidence[]) {
  const assets = new Map<string, { name: string; total: number; counts: number[]; files: Map<string, number> }>()
  for (const finding of findings) {
    const name = finding.pattern || 'Unknown asset'
    const asset = assets.get(name) || { name, total: 0, counts: priorities.map(() => 0), files: new Map<string, number>() }
    const priority = priorities.indexOf(finding.severity.toLowerCase())
    asset.counts[priority < 0 ? priorities.length - 1 : priority]++
    asset.total++
    asset.files.set(finding.file, (asset.files.get(finding.file) || 0) + 1)
    assets.set(name, asset)
  }
  return [...assets.values()].sort((a, b) => b.total - a.total || a.name.localeCompare(b.name))
}
