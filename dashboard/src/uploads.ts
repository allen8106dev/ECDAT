/** Folder entries retain relative paths and are packed without executing their contents. */
export type UploadEntry = { file: File; path: string }
export const MAX_UPLOAD_BYTES = 128 * 1024 * 1024
const MAX_ENTRIES = 20000
const encoder = new TextEncoder()

export function selectedFiles(files: FileList | File[]): UploadEntry[] {
  return Array.from(files, file => ({ file, path: file.webkitRelativePath || file.name }))
}

export async function droppedFiles(items: DataTransferItemList, fallback: FileList): Promise<UploadEntry[]> {
  // Capture entries synchronously, before the browser clears the drag data store.
  const roots = Array.from(items).filter(item => item.kind === 'file').map(item => item.webkitGetAsEntry?.())
  if (!roots.length || roots.some(entry => !entry)) return selectedFiles(fallback)
  const files: UploadEntry[] = []
  let visited = 0
  let bytes = 0
  async function visit(entry: FileSystemEntry, parent = ''): Promise<void> {
    if (++visited > MAX_ENTRIES) throw new Error('The folder has more than 20,000 entries. Choose a smaller folder.')
    const path = parent + entry.name
    if (entry.isFile) {
      const file = await new Promise<File>((resolve, reject) => (entry as FileSystemFileEntry).file(resolve, reject))
      bytes += file.size
      if (bytes > MAX_UPLOAD_BYTES) throw new Error('Folder contents exceed 128 MiB. Choose a smaller folder or upload a compressed ZIP.')
      files.push({ file, path })
    } else if (entry.isDirectory) {
      const reader = (entry as FileSystemDirectoryEntry).createReader()
      // Chromium returns directory entries in batches; read until empty.
      while (true) {
        const batch = await new Promise<FileSystemEntry[]>((resolve, reject) => reader.readEntries(resolve, reject))
        if (!batch.length) break
        for (const child of batch) await visit(child, path + '/')
      }
    }
  }
  for (const root of roots) await visit(root!)
  return files
}

function header(name: string, size: number, type = '0'): Uint8Array<ArrayBuffer> {
  const block = new Uint8Array(512)
  const put = (offset: number, value: string) => block.set(encoder.encode(value), offset)
  put(0, name)
  put(100, '0000644\0')
  put(108, '0000000\0')
  put(116, '0000000\0')
  put(124, size.toString(8).padStart(11, '0') + '\0')
  put(136, '00000000000\0')
  put(148, '        ')
  put(156, type)
  put(257, 'ustar\0')
  put(263, '00')
  const checksum = block.reduce((sum, byte) => sum + byte, 0)
  put(148, checksum.toString(8).padStart(6, '0') + '\0 ')
  return block
}

/** PAX paths support Unicode and long filenames without truncating their locations. */
function pathRecord(path: string): Uint8Array<ArrayBuffer> {
  const record = ` path=${path}\n`
  const bytes = encoder.encode(record).length
  let length = bytes + 1
  while (length !== bytes + String(length).length) length = bytes + String(length).length
  return encoder.encode(`${length}${record}`)
}

export function prepareUpload(entries: UploadEntry[]): File {
  if (!entries.length) throw new Error('The selected folder is empty or contains no accessible files.')
  if (entries.length > MAX_ENTRIES) throw new Error('Choose at most 20,000 files per upload.')
  if (entries.length === 1 && entries[0].path === entries[0].file.name) {
    const file = entries[0].file
    if (!file.size) throw new Error('The selected file is empty. To upload a folder, use Choose folder or drop the folder here.')
    if (file.size > MAX_UPLOAD_BYTES) throw new Error('Choose a file smaller than 128 MiB.')
    return file
  }
  const parts: BlobPart[] = []
  let size = 1024
  const paths = new Set<string>()
  entries.forEach(({ file, path }, index) => {
    if (path.startsWith('/') || path.split('/').some(part => !part || part === '.' || part === '..') ||
        ['\\', '\0', '\r', '\n', ':'].some(character => path.includes(character))) {
      throw new Error('A selected file has an unsupported relative path.')
    }
    if (paths.has(path)) throw new Error(`Duplicate upload path: ${path}`)
    paths.add(path)
    const pax = pathRecord(path)
    const padding = (bytes: number) => new Uint8Array((512 - bytes % 512) % 512)
    const paxPadding = padding(pax.length)
    const filePadding = padding(file.size)
    size += 1024 + pax.length + paxPadding.length + file.size + filePadding.length
    if (size > MAX_UPLOAD_BYTES) throw new Error('Folder archive exceeds 128 MiB. Choose a smaller folder or upload a compressed ZIP.')
    parts.push(header(`PaxHeaders/${index}`, pax.length, 'x'), pax, paxPadding,
      header(`file-${index}`, file.size), file, filePadding)
  })
  parts.push(new Uint8Array(1024))
  const root = entries[0].path.split('/')[0]
  const name = entries.every(entry => entry.path.startsWith(root + '/')) ? root : 'selected-files'
  return new File(parts, `${name}.tar`, { type: 'application/x-tar' })
}
