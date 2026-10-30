svg_content = '''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" fill="none">
  <defs>
    <linearGradient id="shieldBg" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#0b1329" />
      <stop offset="100%" stop-color="#030712" />
    </linearGradient>
    <linearGradient id="glowGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#00f2fe" />
      <stop offset="50%" stop-color="#4facfe" />
      <stop offset="100%" stop-color="#10b981" />
    </linearGradient>
    <linearGradient id="coreGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#38bdf8" />
      <stop offset="100%" stop-color="#10b981" />
    </linearGradient>
    <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
      <feGaussianBlur stdDeviation="2" result="blur" />
      <feComposite in="SourceGraphic" in2="blur" operator="over" />
    </filter>
  </defs>

  <!-- Background Shield Shape -->
  <path d="M32 4 L56 14 C56 36 46 52 32 60 C18 52 8 36 8 14 Z" 
        fill="url(#shieldBg)" 
        stroke="url(#glowGrad)" 
        stroke-width="2.5" 
        stroke-linejoin="round"
        filter="url(#glow)" />

  <!-- Inner Cyber Contour -->
  <path d="M32 10 L50 18 C50 35 42 47 32 53 C22 47 14 35 14 18 Z" 
        fill="none" 
        stroke="url(#glowGrad)" 
        stroke-width="1" 
        stroke-opacity="0.3" />

  <!-- Stylized Monogram "A" with Core Node -->
  <path d="M32 16 L43 40 H37 L34.5 34 H29.5 L27 40 H21 Z M32 23.5 L30.5 30 H33.5 Z" 
        fill="url(#coreGrad)" />

  <!-- Center Verification Node -->
  <circle cx="32" cy="46" r="2.5" fill="#10b981" />
</svg>'''

from pathlib import Path
public_dir = Path(r"c:\Users\SMC-DXB\Projects\Adversum\frontend\public")
(public_dir / "favicon.svg").write_text(svg_content, encoding="utf-8")
print("favicon.svg generated!")
