import { ArrowRight, Check, Eye, EyeOff, LockKeyhole, Mail, ShieldCheck } from 'lucide-react'
import { FormEvent, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import Brand from '../components/Brand'

export default function AuthPage({ mode }: { mode: 'login' | 'register' }) {
  const isRegister = mode === 'register'
  const navigate = useNavigate()
  const [showPassword, setShowPassword] = useState(false)
  const [loading, setLoading] = useState(false)

  function submit(e: FormEvent) {
    e.preventDefault()
    setLoading(true)
    window.setTimeout(() => navigate('/dashboard'), 650)
  }

  return (
    <div className="auth-layout">
      <section className="auth-visual">
        <Brand />
        <div className="auth-visual__content">
          <span className="eyebrow"><span className="status-dot" /> Security intelligence, simplified</span>
          <h1>Convierte señales técnicas en <em>decisiones claras.</em></h1>
          <p>Evalúa rápidamente la postura de seguridad de cualquier superficie web desde una única consola.</p>
          <div className="signal-card">
            <div className="signal-card__top"><span><ShieldCheck size={18} /> Postura global</span><span className="live-label">LIVE</span></div>
            <div className="signal-score"><strong>86</strong><span>/100</span><i>+12%</i></div>
            <div className="signal-bars"><span style={{ height: '38%' }} /><span style={{ height: '52%' }} /><span style={{ height: '44%' }} /><span style={{ height: '68%' }} /><span style={{ height: '58%' }} /><span style={{ height: '82%' }} /><span style={{ height: '72%' }} /><span style={{ height: '92%' }} /></div>
            <div className="signal-card__footer"><span><Check size={14} /> DNS resuelto</span><span><Check size={14} /> TLS válido</span><span>6 cabeceras</span></div>
          </div>
        </div>
        <p className="auth-visual__foot">Análisis local · Resultados estructurados · Recomendaciones accionables</p>
      </section>
      <main className="auth-panel">
        <div className="auth-mobile-brand"><Brand /></div>
        <div className="auth-card">
          <span className="auth-kicker">{isRegister ? 'Crea tu espacio de trabajo' : 'Bienvenido de nuevo'}</span>
          <h2>{isRegister ? 'Empieza a analizar' : 'Accede a tu consola'}</h2>
          <p>{isRegister ? 'Crea tu cuenta para guardar y consultar tus análisis.' : 'Introduce tus credenciales para continuar.'}</p>
          <form onSubmit={submit} className="auth-form">
            {isRegister && <label>Nombre completo<div className="input-wrap"><input required placeholder="Tu nombre" defaultValue="Casper Pérez" /></div></label>}
            <label>Correo electrónico<div className="input-wrap"><Mail size={17} /><input required type="email" placeholder="nombre@empresa.com" defaultValue={!isRegister ? 'casper@intel.dev' : ''} /></div></label>
            <label>Contraseña<div className="input-wrap"><LockKeyhole size={17} /><input required minLength={8} type={showPassword ? 'text' : 'password'} placeholder="Mínimo 8 caracteres" defaultValue={!isRegister ? 'demoPassword!' : ''} /><button type="button" onClick={() => setShowPassword(!showPassword)} aria-label="Mostrar contraseña">{showPassword ? <EyeOff size={17} /> : <Eye size={17} />}</button></div></label>
            {isRegister ? <label className="check-row"><input type="checkbox" required /><span>Acepto los <a href="#terms">términos de uso</a> y la política de privacidad.</span></label> : <div className="form-row"><label className="check-row"><input type="checkbox" /> <span>Recordarme</span></label><a href="#recover">¿Has olvidado tu contraseña?</a></div>}
            <button className="button button--primary button--full" disabled={loading}>{loading ? <><span className="spinner" /> Accediendo…</> : <>{isRegister ? 'Crear cuenta' : 'Iniciar sesión'} <ArrowRight size={17} /></>}</button>
          </form>
          <p className="auth-switch">{isRegister ? '¿Ya tienes una cuenta?' : '¿Todavía no tienes cuenta?'} <Link to={isRegister ? '/login' : '/registro'}>{isRegister ? 'Inicia sesión' : 'Crear cuenta'}</Link></p>
          <div className="demo-note"><span>DEMO</span> Los datos se validan solo visualmente. No se envían credenciales.</div>
        </div>
      </main>
    </div>
  )
}
