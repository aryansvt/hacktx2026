import type { Variant } from "@/lib/creatures";

// small heraldic emblem per creature variant, svg only
const glyphs: Record<Variant, React.ReactNode> = {
  golem: (
    <>
      <rect x="22" y="18" width="20" height="16" rx="2" />
      <rect x="18" y="34" width="28" height="16" rx="2" />
      <circle cx="28" cy="26" r="2" className="eye" />
      <circle cx="36" cy="26" r="2" className="eye" />
    </>
  ),
  "stone-golem": (
    <>
      <path d="M22 16h20l3 18H19z" />
      <path d="M16 34h32l-4 16H20z" />
      <path d="M27 26l3-2M37 26l-3-2" className="line" />
      <path d="M24 40l6 4 4-3 6 3" className="line" />
    </>
  ),
  mage: (
    <>
      <path d="M32 10l12 26H20z" />
      <path d="M18 38h28l-4 14H22z" />
      <circle cx="32" cy="24" r="2" className="eye" />
    </>
  ),
  witch: (
    <>
      <path d="M30 8l16 24H16z" />
      <path d="M12 32h40v3H12z" />
      <path d="M20 37h24l-3 15H23z" />
      <path d="M27 43h10" className="line" />
    </>
  ),
  fae: (
    <>
      <ellipse cx="22" cy="30" rx="9" ry="14" transform="rotate(-20 22 30)" />
      <ellipse cx="42" cy="30" rx="9" ry="14" transform="rotate(20 42 30)" />
      <circle cx="32" cy="34" r="5" className="core" />
    </>
  ),
  "cursed-fae": (
    <>
      <path d="M32 34L12 16l6 22z" />
      <path d="M32 34l20-18-6 22z" />
      <path d="M32 34l-10 16 10-6 10 6z" />
      <circle cx="32" cy="32" r="4" className="core" />
    </>
  ),
  shadow: (
    <>
      <path d="M20 50c0-20 4-34 12-34s12 14 12 34l-4-4-4 4-4-4-4 4-4-4z" />
      <circle cx="28" cy="30" r="2" className="eye" />
      <circle cx="36" cy="30" r="2" className="eye" />
    </>
  ),
  slime: (
    <>
      <path d="M14 48c0-14 8-26 18-26s18 12 18 26z" />
      <circle cx="27" cy="38" r="2.4" className="eye" />
      <circle cx="37" cy="38" r="2.4" className="eye" />
    </>
  ),
  dragon: (
    <>
      <path d="M14 46l10-24 8 8 8-8 10 24-18-6z" />
      <path d="M24 22l-4-10 8 6M40 22l4-10-8 6" />
      <circle cx="28" cy="32" r="2" className="eye" />
      <circle cx="36" cy="32" r="2" className="eye" />
    </>
  ),
};

export default function Emblem({
  variant,
  color,
  size = 64,
}: {
  variant: Variant;
  color: string;
  size?: number;
}) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 64 64"
      aria-hidden
      style={{ color }}
    >
      <defs>
        <radialGradient id={`em-${variant}`} cx="50%" cy="35%" r="70%">
          <stop offset="0%" stopColor="#fff6dc" />
          <stop offset="100%" stopColor="#e1d5bc" />
        </radialGradient>
      </defs>
      <circle cx="32" cy="32" r="30" fill={`url(#em-${variant})`} />
      <circle
        cx="32"
        cy="32"
        r="30"
        fill="none"
        stroke="var(--gold-deep)"
        strokeWidth="2"
      />
      <circle
        cx="32"
        cy="32"
        r="26.5"
        fill="none"
        stroke="var(--gold)"
        strokeWidth="1"
        strokeDasharray="2 3"
      />
      <g
        fill="currentColor"
        stroke="var(--ink)"
        strokeWidth="1.2"
        strokeLinejoin="round"
      >
        {glyphs[variant]}
      </g>
      <style>{`.eye{fill:var(--gold-light);stroke:none}.core{fill:var(--gold-light)}.line{fill:none;stroke:var(--gold-light);stroke-width:1.6}`}</style>
    </svg>
  );
}
