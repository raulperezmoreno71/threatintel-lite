import { ArrowRight, Globe2, LockKeyhole } from 'lucide-react'
import { FormEvent, useState } from 'react'
import { useNavigate } from 'react-router-dom'

export default function UrlScanner({ prominent = false }: { prominent?: boolean }) {
  const navigate = useNavigate()
  const [url, setUrl] = useState('https://github.com')
  const [error, setError] = useState('')

  function submit(e: FormEvent) {
    e.preventDefault()
    try {
      const parsed = new URL(url)
      if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error()
      sessionStorage.setItem('mock-scan-url', url)
      navigate('/analisis/resultado', { state: { loading: true, url } })
    } catch {
      setError('Introduce una URL válida, incluyendo http:// o https://')
    }
  }

  return (
    <form className={`scanner ${prominent ? 'scanner--prominent' : ''}`} onSubmit={submit} noValidate>
      <div className="scanner__intro">
        <span className="scanner__icon"><Globe2 size={22} /></span>
        <div><h2>Analiza una superficie web</h2><p>Inspecciona DNS, HTTP, TLS y cabeceras de seguridad.</p></div>
      </div>
      <div className={`url-field ${error ? 'url-field--error' : ''}`}>
        <LockKeyhole size={18} />
        <input aria-label="URL a analizar" value={url} onChange={(e) => { setUrl(e.target.value); setError('') }} placeholder="https://ejemplo.com" />
        <button className="button button--primary" type="submit">Analizar URL <ArrowRight size={17} /></button>
      </div>
      {error && <p className="form-error">{error}</p>}
      <div className="scanner__meta"><span>Sin peticiones reales en esta demo</span><span>•</span><span>Duración estimada: ~10 s</span></div>
    </form>
  )
}
