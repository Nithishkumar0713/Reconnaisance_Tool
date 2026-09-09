import { useEffect, useState } from 'react'
import { ArrowRight, Shield } from 'lucide-react'
import ReconLogo from './ReconLogo'
import worldMapImg from '../assets/world-map.jpg'

const MAP_NODES = [
  { left: '22%', top: '35%', delay: 0.35 },
  { left: '47%', top: '28%', delay: 0.65 },
  { left: '73%', top: '40%', delay: 0.95 },
  { left: '30%', top: '62%', delay: 1.3 },
  { left: '53%', top: '52%', delay: 1.65 },
  { left: '80%', top: '68%', delay: 2.0 },
]

function AnimatedLetters({ text, startDelay, step = 0.016 }) {
  return text.split('').map((ch, i) => (
    <span
      key={i}
      className="anim-letter"
      style={{ animationDelay: `${startDelay + i * step}s` }}
    >
      {ch === ' ' ? ' ' : ch}
    </span>
  ))
}

export default function LandingPage({ onEnter }) {
  const [visible, setVisible] = useState(false)
  const [leaving, setLeaving] = useState(false)

  useEffect(() => {
    const t = setTimeout(() => setVisible(true), 40)
    return () => clearTimeout(t)
  }, [])

  const HEADER_START = 0.15
  const TITLE_START = 0.6
  const TITLE_LETTERS = 'Reconnaissance Tool'.length
  const LETTER_STEP = 0.016
  const LETTER_DURATION = 0.38
  const TITLE_END = TITLE_START + (TITLE_LETTERS - 1) * LETTER_STEP + LETTER_DURATION
  const TAGLINE_START = TITLE_END + 0.08
  const LOGO_START = TAGLINE_START + 0.2
  const BUTTON_START = LOGO_START + 0.45
  const FOOTER_START = BUTTON_START + 0.2

  const handleEnter = () => {
    if (leaving) return
    setLeaving(true)
    setTimeout(() => onEnter(), 80)
  }

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
        className="absolute inset-0 bg-no-repeat bg-center -z-20 pointer-events-none anim-map"
        style={{
          backgroundImage: `url(${worldMapImg})`,
          backgroundSize: 'cover',
          backgroundPosition: 'center center',
          filter: 'brightness(115%) contrast(120%) saturate(130%)',
          mixBlendMode: 'darken',
        }}
      />
      <div className="-z-20 pointer-events-none anim-scanline blur-sm" />

      {MAP_NODES.map((node, i) => (
        <span
          key={i}
          className="absolute -z-[15] pointer-events-none map-node"
          style={{ left: node.left, top: node.top, animationDelay: `${node.delay}s` }}
        />
      ))}

      <div 
        className="absolute inset-0 -z-10 pointer-events-none"
        style={{
          background: 'radial-gradient(circle at center, rgba(224, 242, 254, 0.40) 0%, rgba(204, 251, 241, 0.35) 60%, rgba(186, 230, 253, 0.50) 100%)',
        }}
      />

      <header
        className="relative z-10 border-b border-orange-400 bg-gradient-to-r from-orange-600 via-orange-500 to-amber-500 shadow-md anim-fade-up"
        style={{ animationDelay: `${HEADER_START}s` }}
      >
        <div className="max-w-7xl mx-auto px-6 py-4.5 sm:py-5 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="w-11 h-11 sm:w-12 sm:h-12 rounded-full bg-orange-700/40 border border-orange-400/50 flex items-center justify-center text-white shadow-inner">
              <ReconLogo className="w-6 h-6 sm:w-7 sm:h-7" style={{ color: 'white' }} />
            </div>
            <div>
              <div className="text-lg sm:text-xl font-extrabold tracking-wide text-white leading-tight">
                Reconnaissance Tool
              </div>
              <div className="text-[10px] sm:text-xs text-orange-50 font-bold uppercase tracking-widest mt-0.5">
                Host Diagnostics
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2.5 sm:gap-3 text-white text-sm sm:text-base font-extrabold tracking-wide">
            <Shield className="w-5 h-5 sm:w-6 sm:h-6 text-white" strokeWidth={2.5} />
            <span>Secure • Fast • Reliable</span>
          </div>
        </div>
      </header>

      <div className="relative z-10 flex-1 flex flex-col items-center justify-center text-center px-6 py-12 gap-6 max-w-4xl mx-auto">

        <div className="flex items-center justify-center gap-3.5 sm:gap-4 flex-wrap">
          <div className="relative flex-shrink-0">
            <div
              className="absolute inset-0 rounded-full anim-ring"
              style={{
                animationDelay: `${LOGO_START}s`,
                background: 'radial-gradient(circle, rgba(245,158,11,0.55), transparent 70%)',
              }}
            />
            <div
              className="anim-logo w-14 h-14 sm:w-16 sm:h-16 rounded-full bg-gradient-to-br from-orange-500 to-amber-400 flex items-center justify-center shadow-lg glow-sage"
              style={{ animationDelay: `${LOGO_START}s` }}
            >
              <ReconLogo className="w-8 h-8 sm:w-9 sm:h-9" style={{ color: 'white' }} />
            </div>
          </div>
          <h1 className="text-4xl sm:text-5xl md:text-6xl font-black tracking-tight text-slate-900 leading-none">
            <AnimatedLetters text="Reconnaissance " startDelay={TITLE_START} />
            <span className="text-orange-600">
              <AnimatedLetters text="Tool" startDelay={TITLE_START + 'Reconnaissance '.length * LETTER_STEP} />
            </span>
          </h1>
        </div>

        <p
          className="anim-fade-up text-slate-600 text-sm sm:text-base md:text-lg font-semibold max-w-none whitespace-nowrap leading-relaxed mt-1"
          style={{ animationDelay: `${TAGLINE_START}s` }}
        >
          Bringing multiple aspects of reconnaissance into a single platform.
        </p>

        <button
          onClick={handleEnter}
          className="anim-fade-up mt-3 flex items-center gap-3 px-8 py-4 rounded-2xl text-white font-bold text-base tracking-wide shadow-md transition-all duration-200 hover:shadow-xl hover:-translate-y-0.5 active:translate-y-0 cursor-pointer glow-sage"
          style={{ background: 'linear-gradient(135deg, #ea580c, #f59e0b)', animationDelay: `${BUTTON_START}s` }}
        >
          Get Started
          <ArrowRight className="w-5 h-5" />
        </button>

      </div>

      <footer
        className="relative z-10 border-t border-slate-300/80 bg-white/40 backdrop-blur-sm py-4 anim-fade-up"
        style={{ animationDelay: `${FOOTER_START}s` }}
      >
        <div className="max-w-6xl mx-auto px-6 text-center">
          <p className="text-xs font-semibold text-slate-600 tracking-wide">
            <span className="font-bold text-slate-800">Note : </span>Perform reconnaissance responsibly and only on assets you own or are explicitly authorized to assess.
          </p>
        </div>
      </footer>
    </div>
  )
}
