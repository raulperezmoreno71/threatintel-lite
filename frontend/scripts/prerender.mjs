import { readFile, writeFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { createServer } from 'vite'

const indexPath = resolve('dist/index.html')
const server = await createServer({ server: { middlewareMode: true }, appType: 'custom' })

try {
  const { renderLandingPage } = await server.ssrLoadModule('/src/entry-server.tsx')
  const html = await readFile(indexPath, 'utf8')
  const placeholder = '<div id="root"></div>'

  if (!html.includes(placeholder)) {
    throw new Error('No se encontró el contenedor de React en dist/index.html')
  }

  await writeFile(
    indexPath,
    html.replace(placeholder, `<div id="root">${renderLandingPage()}</div>`),
  )
} finally {
  await server.close()
}
