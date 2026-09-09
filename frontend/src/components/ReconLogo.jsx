export default function ReconLogo({ className = '', style = {} }) {
  return (
    <svg
      viewBox="0 0 36 36"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      style={style}
      aria-label="Reconnaissance Tool Logo"
    >
      <circle cx="14" cy="14" r="12" stroke="currentColor" strokeWidth="1.8" fill="none" />

      <ellipse cx="14" cy="14" rx="5" ry="12" stroke="currentColor" strokeWidth="1.4" fill="none" />

      <line x1="2" y1="14" x2="26" y2="14" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />

      <path d="M5 8.5 Q14 6 23 8.5" stroke="currentColor" strokeWidth="1.2" fill="none" strokeLinecap="round" />

      <path d="M5 19.5 Q14 22 23 19.5" stroke="currentColor" strokeWidth="1.2" fill="none" strokeLinecap="round" />

      <circle cx="24" cy="24" r="7" stroke="currentColor" strokeWidth="2" fill="none" />

      <line x1="29" y1="29" x2="34" y2="34" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" />
    </svg>
  )
}
