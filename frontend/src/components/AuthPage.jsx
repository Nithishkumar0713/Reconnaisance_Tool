import { useState, useEffect } from 'react'
import ReconLogo from './ReconLogo'
import worldMapImg from '../assets/world-map.jpg'
import {
  Mail, Lock, User, Eye, EyeOff, ArrowRight,
  AlertCircle, Shield, RefreshCw, CheckCircle, KeyRound
} from 'lucide-react'

const API_BASE = import.meta.env.DEV ? '/api' : ''

function makeCaptcha() {
  const ops = ['+', '-', '×']
  const op = ops[Math.floor(Math.random() * ops.length)]
  let a = Math.floor(Math.random() * 9) + 1
  let b = Math.floor(Math.random() * 9) + 1
  let ans
  if (op === '+') {
    ans = a + b
  } else if (op === '-') {
    if (a < b) [a, b] = [b, a]
    ans = a - b
  } else {
    a = Math.floor(Math.random() * 5) + 1
    b = Math.floor(Math.random() * 5) + 1
    ans = a * b
  }
  return { a, b, op, ans }
}

export default function AuthPage({ onAuthSuccess, sessionExpiredReason }) {
  const [visible, setVisible] = useState(false)
  const [leaving, setLeaving] = useState(false)

  const [isSignUp, setIsSignUp] = useState(false)
  const [sliding, setSliding] = useState(false)

  const [showPass, setShowPass] = useState(false)
  const [showConfirmPass, setShowConfirmPass] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [successMessage, setSuccessMessage] = useState('')

  const [loginForm, setLoginForm] = useState({ email: '', password: '' })

  const [captcha, setCaptcha] = useState(() => makeCaptcha())
  const [captchaInput, setCaptchaInput] = useState('')
  const [captchaShake, setCaptchaShake] = useState(false)

  const [registerForm, setRegisterForm] = useState({ name: '', email: '', password: '', confirm: '' })

  const [otpSent, setOtpSent] = useState(false)
  const [otpCode, setOtpCode] = useState('')
  const [sendingOtp, setSendingOtp] = useState(false)
  const [otpCooldown, setOtpCooldown] = useState(0)

  useEffect(() => {
    const t = setTimeout(() => setVisible(true), 20)
    return () => clearTimeout(t)
  }, [])

  useEffect(() => {
    if (otpCooldown <= 0) return
    const t = setInterval(() => setOtpCooldown(prev => Math.max(0, prev - 1)), 1000)
    return () => clearInterval(t)
  }, [otpCooldown])

  const validatePassword = (pass) => ({
    length:    pass.length >= 8,
    maxLength: pass.length <= 72,
    uppercase: /[A-Z]/.test(pass),
    number:    /[0-9]/.test(pass),
    special:   /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?`~]/.test(pass),
  })
  const pwStatus = validatePassword(registerForm.password)
  const allPwMet = Object.values(pwStatus).every(Boolean)

  const switchMode = (toSignUp) => {
    if (sliding || toSignUp === isSignUp) return
    setError('')
    setOtpSent(false)
    setOtpCode('')
    setOtpCooldown(0)
    setSliding(true)
    setTimeout(() => { setIsSignUp(toSignUp); setSliding(false) }, 350)
  }

  const refreshCaptcha = () => {
    setCaptcha(makeCaptcha())
    setCaptchaInput('')
    setCaptchaShake(false)
  }

  const shakeCaptcha = () => {
    setCaptchaShake(true)
    setTimeout(() => setCaptchaShake(false), 500)
    refreshCaptcha()
  }

  const handleLogin = async (e) => {
    e.preventDefault()
    setError('')
    setSuccessMessage('')

    if (parseInt(captchaInput, 10) !== captcha.ans) {
      setError('Incorrect security answer. A new question has been generated.')
      shakeCaptcha()
      return
    }

    setLoading(true)
    try {
      const res = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: loginForm.email, password: loginForm.password }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail || 'Login failed')
      localStorage.setItem('recon_token', data.access_token)
      localStorage.setItem('recon_user', JSON.stringify({
        id: data.user_id, name: data.full_name, email: data.email
      }))

      try {
        const storedHistory = JSON.parse(localStorage.getItem('recon_login_history') || '[]')
        const newEntry = { timestamp: new Date().toISOString(), type: 'Web Session Login' }
        const updatedHistory = [newEntry, ...storedHistory].slice(0, 15)
        localStorage.setItem('recon_login_history', JSON.stringify(updatedHistory))
      } catch (e) {
        console.error('Failed to log login timestamp:', e)
      }

      setLeaving(true)
      setTimeout(() => onAuthSuccess(), 80)
    } catch (err) {
      setError(err.message)
      refreshCaptcha()
    } finally {
      setLoading(false)
    }
  }

  const handleSendOtp = async () => {
    setError('')
    setSuccessMessage('')
    if (!registerForm.name.trim())   { setError('Please enter your full name.'); return }
    if (!registerForm.email)         { setError('Please enter your email address.'); return }
    if (!registerForm.password)      { setError('Please enter a password.'); return }
    if (!allPwMet)                   { setError('Password does not meet all requirements.'); return }
    if (registerForm.password !== registerForm.confirm) {
      setError('Passwords do not match.')
      return
    }

    setSendingOtp(true)
    try {
      const res = await fetch(`${API_BASE}/auth/send-otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: registerForm.email, full_name: registerForm.name }),
      }).catch(() => { throw new Error('Cannot reach backend — make sure the server is running on port 8000.') })
      const data = await res.json().catch(() => ({ detail: 'Backend returned an unexpected response. Check the server terminal for errors.' }))
      if (!res.ok) throw new Error(data.detail || 'Failed to send verification code')
      setOtpSent(true)
      setOtpCooldown(60)
      setOtpCode('')
    } catch (err) {
      setError(err.message)
    } finally {
      setSendingOtp(false)
    }
  }

  const handleRegister = async (e) => {
    e.preventDefault()
    setError('')
    setSuccessMessage('')
    if (!otpCode.trim()) { setError('Please enter the verification code.'); return }

    setLoading(true)
    try {
      const res = await fetch(`${API_BASE}/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          full_name: registerForm.name,
          email: registerForm.email,
          password: registerForm.password,
          otp: otpCode.trim(),
        }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail || 'Registration failed')
      
      const registeredEmail = registerForm.email
      setLoginForm({ email: registeredEmail, password: '' })
      setRegisterForm({ name: '', email: '', password: '', confirm: '' })
      setOtpSent(false)
      setOtpCode('')
      setOtpCooldown(0)
      setSuccessMessage('Account created successfully! Please sign in with your credentials.')
      refreshCaptcha()
      switchMode(false)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const inputCls = 'w-full pl-9 pr-4 py-2.5 border border-slate-200 rounded-lg text-sm focus:outline-none focus:border-orange-400 focus:ring-1 focus:ring-orange-200 bg-slate-50 text-slate-800 transition'
  const inputWithToggleCls = 'w-full pl-9 pr-10 py-2.5 border border-slate-200 rounded-lg text-sm focus:outline-none focus:border-orange-400 focus:ring-1 focus:ring-orange-200 bg-slate-50 text-slate-800 transition'

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 9999,
        opacity: leaving ? 0 : visible ? 1 : 0,
        transition: 'opacity 0.15s ease-in-out',
        pointerEvents: leaving ? 'none' : 'auto',
      }}
      className="min-h-screen relative flex flex-col overflow-hidden select-none"
    >
      <div className="absolute inset-0 bg-gradient-to-tr from-[#bae6fd] via-[#e0f2fe] to-[#ccfbf1] -z-30" />

      <div
        className="absolute inset-0 bg-no-repeat bg-center -z-20 pointer-events-none transition-all duration-300"
        style={{
          backgroundImage: `url(${worldMapImg})`,
          backgroundSize: 'cover',
          backgroundPosition: 'center center',
          opacity: 0.18,
          filter: 'brightness(115%) contrast(120%) saturate(130%)',
          mixBlendMode: 'darken',
        }}
      />

      <div 
        className="absolute inset-0 -z-10 pointer-events-none"
        style={{
          background: 'radial-gradient(circle at center, rgba(224, 242, 254, 0.40) 0%, rgba(204, 251, 241, 0.35) 60%, rgba(186, 230, 253, 0.50) 100%)',
        }}
      />

      <header className="relative z-10 border-b border-orange-400 bg-gradient-to-r from-orange-600 via-orange-500 to-amber-500 shadow-md">
        <div className="max-w-7xl mx-auto px-6 py-4.5 sm:py-5 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="w-11 h-11 sm:w-12 sm:h-12 rounded-full bg-orange-700/40 border border-orange-400/50 flex items-center justify-center shadow-inner">
              <ReconLogo className="w-6 h-6 sm:w-7 sm:h-7" style={{ color: 'white' }} />
            </div>
            <div>
              <div className="text-lg sm:text-xl font-extrabold tracking-wide text-white leading-tight">Reconnaissance Tool</div>
              <div className="text-[10px] sm:text-xs text-orange-50 font-bold uppercase tracking-widest mt-0.5">Host Diagnostics</div>
            </div>
          </div>
          <div className="flex items-center gap-2.5 sm:gap-3 text-white text-sm sm:text-base font-extrabold tracking-wide">
            <Shield className="w-5 h-5 sm:w-6 sm:h-6 text-white" strokeWidth={2.5} />
            <span>Secure • Fast • Reliable</span>
          </div>
        </div>
      </header>

      <div className="relative z-10 flex-1 flex items-center justify-center px-4 py-12">
        <div
          className="relative w-full max-w-3xl rounded-2xl shadow-2xl overflow-hidden"
          style={{ height: 560, background: 'white' }}
        >

          <div
            className="absolute top-0 left-0 w-1/2 h-full flex flex-col items-center justify-center px-10 py-10 overflow-y-auto"
            style={{
              opacity: isSignUp ? 0 : 1,
              pointerEvents: isSignUp ? 'none' : 'auto',
              transition: 'opacity 0.3s ease',
              zIndex: 1,
            }}
          >
            <h2 className="text-3xl font-black text-slate-800 mb-1">Welcome Back!</h2>
            <p className="text-slate-400 text-sm mb-4 text-center">Sign in to continue your reconnaissance journey.</p>

            {sessionExpiredReason && (
              <div className="w-full mb-3 p-3 rounded-xl bg-amber-50 border border-amber-300 text-amber-900 text-xs font-bold flex items-center gap-2 shadow-xs animate-fade-in">
                <AlertCircle className="w-4 h-4 text-amber-600 flex-shrink-0" />
                <span>{sessionExpiredReason}</span>
              </div>
            )}

            <form onSubmit={handleLogin} className="w-full flex flex-col gap-3">

              <div>
                <label className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-1 block">Email Address</label>
                <div className="relative">
                  <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                  <input
                    type="email"
                    placeholder="Enter your email"
                    value={loginForm.email}
                    onChange={e => setLoginForm(p => ({ ...p, email: e.target.value }))}
                    required
                    className={inputCls}
                  />
                </div>
              </div>

              <div>
                <label className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-1 block">Password</label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                  <input
                    type={showPass ? 'text' : 'password'}
                    placeholder="Enter your password"
                    value={loginForm.password}
                    onChange={e => setLoginForm(p => ({ ...p, password: e.target.value }))}
                    required
                    className={inputWithToggleCls}
                  />
                  <button type="button" onClick={() => setShowPass(p => !p)} className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600">
                    {showPass ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              <div>
                <label className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-1.5 block">Security Check</label>
                <div className={`flex items-center gap-2 ${captchaShake ? 'animate-[shake_0.5s_ease]' : ''}`}>
                  <div className="flex-1 bg-orange-50 border-2 border-orange-200 rounded-lg px-3 py-2 flex items-center justify-center">
                    <span className="font-black text-orange-700 text-base mono tracking-wider select-none">
                      {captcha.a} {captcha.op} {captcha.b} = ?
                    </span>
                  </div>
                  <input
                    type="number"
                    placeholder="Ans"
                    value={captchaInput}
                    onChange={e => setCaptchaInput(e.target.value)}
                    required
                    className="w-16 px-2 py-2 border border-slate-200 rounded-lg text-sm text-center font-bold focus:outline-none focus:border-orange-400 focus:ring-1 focus:ring-orange-200 bg-slate-50 text-slate-800 transition"
                  />
                  <button
                    type="button"
                    onClick={refreshCaptcha}
                    title="New question"
                    className="p-2 rounded-lg border border-slate-200 hover:border-orange-300 hover:bg-orange-50 text-slate-400 hover:text-orange-500 transition"
                  >
                    <RefreshCw className="w-4 h-4" />
                  </button>
                </div>
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full py-3 rounded-xl text-white font-bold text-sm tracking-wide mt-1 transition-all duration-200 hover:shadow-lg hover:-translate-y-0.5 flex items-center justify-center gap-2 disabled:opacity-60 disabled:cursor-not-allowed"
                style={{ background: 'linear-gradient(135deg, #ea580c, #f59e0b)' }}
              >
                {loading && !isSignUp ? 'Signing in...' : <><span>Sign In</span><ArrowRight className="w-4 h-4" /></>}
              </button>

              {successMessage && !isSignUp && (
                <div className="flex items-center gap-2 text-teal-700 text-xs font-semibold bg-teal-50 border border-teal-200 rounded-lg px-3 py-2">
                  <CheckCircle className="w-4 h-4 flex-shrink-0 text-teal-600" />{successMessage}
                </div>
              )}

              {error && !isSignUp && (
                <div className="flex items-center gap-2 text-red-500 text-xs font-semibold bg-red-50 border border-red-200 rounded-lg px-3 py-2">
                  <AlertCircle className="w-4 h-4 flex-shrink-0" />{error}
                </div>
              )}
            </form>
          </div>

          <div
            className="absolute top-0 right-0 w-1/2 h-full flex flex-col items-center justify-center px-10 py-8 overflow-y-auto"
            style={{
              opacity: isSignUp ? 1 : 0,
              pointerEvents: isSignUp ? 'auto' : 'none',
              transition: 'opacity 0.3s ease',
              zIndex: 1,
            }}
          >
            {!otpSent ? (
              <>
                <h2 className="text-3xl font-black text-slate-800 mb-1">Create Account</h2>
                <p className="text-slate-400 text-sm mb-4 text-center">Create your account to get started.</p>

                <div className="w-full flex flex-col gap-2.5">
                  <div className="relative">
                    <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                    <input
                      type="text"
                      placeholder="Full name"
                      value={registerForm.name}
                      onChange={e => setRegisterForm(p => ({ ...p, name: e.target.value }))}
                      className={inputCls}
                    />
                  </div>

                  <div className="relative">
                    <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                    <input
                      type="email"
                      placeholder="Email address"
                      value={registerForm.email}
                      onChange={e => setRegisterForm(p => ({ ...p, email: e.target.value }))}
                      className={inputCls}
                    />
                  </div>

                  <div className="relative">
                    <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                    <input
                      type={showPass ? 'text' : 'password'}
                      placeholder="Create a password"
                      value={registerForm.password}
                      onChange={e => setRegisterForm(p => ({ ...p, password: e.target.value }))}
                      className={inputWithToggleCls}
                    />
                    <button type="button" onClick={() => setShowPass(p => !p)} className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600">
                      {showPass ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>

                  {registerForm.password && (
                    <div className="text-[11px] p-2 bg-slate-50 border border-slate-200 rounded-lg flex flex-col gap-1 animate-fade-in">
                      <div className="font-bold text-slate-400 uppercase tracking-wider text-[9px] mb-0.5">Requirements:</div>
                      {[
                        [pwStatus.length,    'Min 8 characters'],
                        [pwStatus.maxLength, 'Max 72 characters'],
                        [pwStatus.uppercase, 'One uppercase (A-Z)'],
                        [pwStatus.number,    'One number (0-9)'],
                        [pwStatus.special,   'One special (!@#$%^ etc.)'],
                      ].map(([ok, label]) => (
                        <div key={label} className="flex items-center gap-1.5">
                          <span className={`w-1.5 h-1.5 rounded-full transition-all duration-300 ${ok ? 'bg-teal-500 scale-110' : 'bg-red-300'}`} />
                          <span className={ok ? 'text-teal-700 font-semibold' : 'text-slate-400'}>{label}</span>
                        </div>
                      ))}
                    </div>
                  )}

                  <div className="relative">
                    <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                    <input
                      type={showConfirmPass ? 'text' : 'password'}
                      placeholder="Confirm your password"
                      value={registerForm.confirm}
                      onChange={e => setRegisterForm(p => ({ ...p, confirm: e.target.value }))}
                      className={inputWithToggleCls}
                    />
                    <button type="button" onClick={() => setShowConfirmPass(p => !p)} className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600">
                      {showConfirmPass ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>

                  <button
                    type="button"
                    onClick={handleSendOtp}
                    disabled={sendingOtp}
                    className="w-full py-3 rounded-xl text-white font-bold text-sm tracking-wide mt-1 transition-all duration-200 hover:shadow-lg hover:-translate-y-0.5 flex items-center justify-center gap-2 disabled:opacity-60 disabled:cursor-not-allowed"
                    style={{ background: 'linear-gradient(135deg, #ea580c, #f59e0b)' }}
                  >
                    {sendingOtp
                      ? 'Sending Code...'
                      : <><Mail className="w-4 h-4" /><span>Send Verification Code</span></>}
                  </button>

                  {error && isSignUp && (
                    <div className="flex items-center gap-2 text-red-500 text-xs font-semibold bg-red-50 border border-red-200 rounded-lg px-3 py-2">
                      <AlertCircle className="w-4 h-4 flex-shrink-0" />{error}
                    </div>
                  )}
                </div>
              </>
            ) : (
              <form onSubmit={handleRegister} className="w-full flex flex-col items-center gap-4">
                <div className="w-14 h-14 rounded-full bg-orange-50 border-2 border-orange-200 flex items-center justify-center">
                  <Mail className="w-6 h-6 text-orange-500" />
                </div>

                <div className="text-center">
                  <h2 className="text-2xl font-black text-slate-800 mb-1">Check Your Email</h2>
                  <p className="text-slate-400 text-sm">We sent a 6-digit code to</p>
                  <p className="text-orange-600 font-bold text-sm mt-0.5">{registerForm.email}</p>
                </div>

                <div className="w-full">
                  <label className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-2 block text-center">
                    Enter Verification Code
                  </label>
                  <div className="relative">
                    <KeyRound className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                    <input
                      type="text"
                      inputMode="numeric"
                      maxLength={6}
                      placeholder="• • • • • •"
                      value={otpCode}
                      onChange={e => setOtpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                      required
                      autoFocus
                      className="w-full pl-9 pr-4 py-3 border-2 border-slate-200 rounded-lg text-center text-2xl font-black tracking-[0.5em] focus:outline-none focus:border-orange-400 focus:ring-1 focus:ring-orange-200 bg-slate-50 text-slate-800 transition mono"
                    />
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={loading || otpCode.length < 6}
                  className="w-full py-3 rounded-xl text-white font-bold text-sm tracking-wide transition-all duration-200 hover:shadow-lg hover:-translate-y-0.5 flex items-center justify-center gap-2 disabled:opacity-60 disabled:cursor-not-allowed"
                  style={{ background: 'linear-gradient(135deg, #ea580c, #f59e0b)' }}
                >
                  {loading
                    ? 'Verifying...'
                    : <><CheckCircle className="w-4 h-4" /><span>Verify & Create Account</span></>}
                </button>

                <div className="flex items-center justify-between w-full">
                  <button
                    type="button"
                    onClick={() => { setOtpSent(false); setOtpCode(''); setError('') }}
                    className="text-xs text-slate-400 hover:text-slate-600 font-semibold transition"
                  >
                    ← Change email
                  </button>
                  <button
                    type="button"
                    onClick={otpCooldown > 0 ? undefined : handleSendOtp}
                    disabled={sendingOtp || otpCooldown > 0}
                    className="text-xs text-orange-500 hover:text-orange-700 font-bold transition disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {otpCooldown > 0
                      ? `Resend in ${otpCooldown}s`
                      : sendingOtp ? 'Sending...' : 'Resend Code'}
                  </button>
                </div>

                {error && isSignUp && (
                  <div className="flex items-center gap-2 text-red-500 text-xs font-semibold bg-red-50 border border-red-200 rounded-lg px-3 py-2 w-full">
                    <AlertCircle className="w-4 h-4 flex-shrink-0" />{error}
                  </div>
                )}
              </form>
            )}
          </div>

          <div
            className="absolute top-0 h-full w-1/2 flex flex-col items-center justify-center px-10 text-center"
            style={{
              left: isSignUp ? '0%' : '50%',
              background: 'linear-gradient(145deg, #ea580c 0%, #f97316 50%, #f59e0b 100%)',
              transition: 'left 0.4s cubic-bezier(0.77,0,0.175,1)',
              zIndex: 10,
              borderRadius: isSignUp ? '16px 0 0 16px' : '0 16px 16px 0',
            }}
          >
            {!isSignUp ? (
              <div style={{ opacity: sliding ? 0 : 1, transform: sliding ? 'scale(0.96)' : 'scale(1)', transition: 'opacity 0.2s ease, transform 0.2s ease' }}>
                <div className="w-16 h-16 rounded-full bg-white/20 flex items-center justify-center mx-auto mb-5">
                  <ReconLogo className="w-8 h-8" style={{ color: 'white' }} />
                </div>
                <h3 className="text-2xl font-black text-white mb-3">Hello, Friend!</h3>
                <p className="text-orange-100 text-sm leading-relaxed mb-7 max-w-xs">
                  New here? Create an account and start your reconnaissance journey.
                </p>
                <button
                  onClick={() => switchMode(true)}
                  className="px-8 py-2.5 rounded-full border-2 border-white text-white font-bold text-sm tracking-widest uppercase hover:bg-white hover:text-orange-600 transition-all duration-200"
                >
                  Sign Up
                </button>
              </div>
            ) : (
              <div style={{ opacity: sliding ? 0 : 1, transform: sliding ? 'scale(0.96)' : 'scale(1)', transition: 'opacity 0.2s ease, transform 0.2s ease' }}>
                <div className="w-16 h-16 rounded-full bg-white/20 flex items-center justify-center mx-auto mb-5">
                  <ReconLogo className="w-8 h-8" style={{ color: 'white' }} />
                </div>
                <h3 className="text-2xl font-black text-white mb-3">Welcome Back!</h3>
                <p className="text-orange-100 text-sm leading-relaxed mb-7 max-w-xs">
                  Already have an account? Sign in to continue your recon sessions.
                </p>
                <button
                  onClick={() => switchMode(false)}
                  className="px-8 py-2.5 rounded-full border-2 border-white text-white font-bold text-sm tracking-widest uppercase hover:bg-white hover:text-orange-600 transition-all duration-200"
                >
                  Sign In
                </button>
              </div>
            )}
          </div>

        </div>
      </div>

      <footer className="border-t border-slate-300 bg-white/50 py-5 shadow-inner">
        <div className="max-w-6xl mx-auto px-6 text-center">
          <p className="text-xs font-semibold text-slate-500 tracking-wide">
            <span className="font-bold text-slate-700">Note : </span>Perform reconnaissance responsibly and only on assets you own or are explicitly authorized to assess.
          </p>
        </div>
      </footer>
    </div>
  )
}
