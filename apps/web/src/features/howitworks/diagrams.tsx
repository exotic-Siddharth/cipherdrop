/**
 * Inline SVG diagrams for /how-it-works (spec 11.2). Colours come from the theme tokens through Tailwind's
 * fill-* / stroke-* utilities, so they follow light and dark mode. Every diagram is a labelled image with a
 * text description; the surrounding page repeats the content in prose.
 */
import type { ReactNode } from 'react';
import { cn } from '../../lib/cn';

const BOX = 'fill-surface stroke-border-strong';
const BOX_PRIMARY = 'fill-primary/10 stroke-primary';
const LINE = 'stroke-border-strong';
const T_MAIN = 'fill-foreground';
const T_MUTED = 'fill-muted-strong';
const T_PRIMARY = 'fill-primary-ink';

interface DiagramFrameProps {
  title: string;
  description: string;
  viewBox: string;
  children: ReactNode;
  className?: string;
}

function DiagramFrame({ title, description, viewBox, children, className }: DiagramFrameProps) {
  const titleId = `${title.replace(/\W+/g, '-').toLowerCase()}-title`;
  return (
    <svg
      viewBox={viewBox}
      role="img"
      aria-labelledby={titleId}
      className={cn('block h-auto w-full font-sans', className)}
      xmlns="http://www.w3.org/2000/svg"
    >
      <title id={titleId}>{`${title}. ${description}`}</title>
      {children}
    </svg>
  );
}

/** A downward arrow: shaft from (x, y1) to (x, y2) with a head at y2. */
function ArrowDown({
  x,
  y1,
  y2,
  className,
}: {
  x: number;
  y1: number;
  y2: number;
  className?: string;
}) {
  return (
    <g className={className ?? LINE} strokeWidth={2} fill="none">
      <line x1={x} y1={y1} x2={x} y2={y2 - 6} strokeLinecap="round" />
      <path
        d={`M${x - 5} ${y2 - 8} L${x} ${y2 - 1} L${x + 5} ${y2 - 8}`}
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </g>
  );
}

/** (1) The key sits after the # of the link, which browsers never send to a server. */
export function FragmentDiagram({ className }: { className?: string }) {
  return (
    <DiagramFrame
      title="The key lives after the hash"
      description="A share link is split in two. The part before the hash goes to the server. The key after the hash stays in your browser."
      viewBox="0 0 480 250"
      className={className}
    >
      <rect
        x={8}
        y={14}
        width={464}
        height={56}
        rx={28}
        className="fill-surface-2 stroke-border-strong"
        strokeWidth={1.5}
      />
      <text x={34} y={48} className={cn('font-mono', T_MAIN)} fontSize={16}>
        cipherdrop.app/d/Qm4xz8
      </text>
      <rect x={264} y={26} width={158} height={32} rx={16} className="fill-primary/15" />
      <text x={278} y={48} className={cn('font-mono font-semibold', T_PRIMARY)} fontSize={16}>
        #7Fq2K…Xb9
      </text>

      <ArrowDown x={140} y1={72} y2={118} />
      <ArrowDown x={343} y1={72} y2={118} className="stroke-primary" />

      <rect x={8} y={122} width={224} height={116} rx={14} className={BOX} strokeWidth={1.5} />
      <text x={24} y={150} className={cn('font-semibold', T_MAIN)} fontSize={17}>
        Our server
      </text>
      <text x={24} y={176} className={T_MUTED} fontSize={14.5}>
        Receives the link up to
      </text>
      <text x={24} y={196} className={T_MUTED} fontSize={14.5}>
        the hash and serves
      </text>
      <text x={24} y={216} className={T_MUTED} fontSize={14.5}>
        encrypted bytes
      </text>

      <rect
        x={248}
        y={122}
        width={224}
        height={116}
        rx={14}
        className={BOX_PRIMARY}
        strokeWidth={1.5}
      />
      <text x={264} y={150} className={cn('font-semibold', T_PRIMARY)} fontSize={17}>
        Your browser
      </text>
      <text x={264} y={176} className={T_MAIN} fontSize={14.5}>
        Keeps the key after the
      </text>
      <text x={264} y={196} className={T_MAIN} fontSize={14.5}>
        hash and decrypts the
      </text>
      <text x={264} y={216} className={T_MAIN} fontSize={14.5}>
        file on your device
      </text>
    </DiagramFrame>
  );
}

const CHUNK_X = [8, 126, 244, 362] as const;
const CHUNK_LABELS = ['chunk 0', 'chunk 1', 'chunk 2', 'last chunk'] as const;
const NONCE_LABELS = ['index 0', 'index 1', 'index 2', 'index 3 + last'] as const;

/** (2) Chunked STREAM encryption: 4 MiB chunks, each sealed with AES-256-GCM and a position-bound nonce. */
export function StreamDiagram({ className }: { className?: string }) {
  return (
    <DiagramFrame
      title="Chunked encryption"
      description="A file is cut into 4 MiB chunks. Each chunk is sealed with AES-256-GCM using a nonce built from its position and a last-chunk flag, so reordering or truncating is detected."
      viewBox="0 0 480 312"
      className={className}
    >
      <text x={8} y={20} className={cn('font-semibold', T_MUTED)} fontSize={13.5}>
        YOUR FILE, CUT INTO 4 MiB CHUNKS
      </text>
      {CHUNK_X.map((x, i) => (
        <g key={`plain-${x}`}>
          <rect x={x} y={32} width={104} height={44} rx={10} className={BOX} strokeWidth={1.5} />
          <text x={x + 52} y={59} textAnchor="middle" className={T_MAIN} fontSize={14.5}>
            {CHUNK_LABELS[i]}
          </text>
        </g>
      ))}

      <ArrowDown x={240} y1={80} y2={122} className="stroke-primary" />
      <text x={254} y={108} className={cn('font-medium', T_PRIMARY)} fontSize={14.5}>
        AES-256-GCM
      </text>

      <text x={8} y={146} className={cn('font-semibold', T_MUTED)} fontSize={13.5}>
        WHAT GETS STORED
      </text>
      {CHUNK_X.map((x, i) => (
        <g key={`sealed-${x}`}>
          <rect
            x={x}
            y={158}
            width={104}
            height={44}
            rx={10}
            className={BOX_PRIMARY}
            strokeWidth={1.5}
          />
          <rect
            x={x + 76}
            y={158}
            width={28}
            height={44}
            rx={10}
            className="fill-primary/25 stroke-primary"
            strokeWidth={1.5}
          />
          <text
            x={x + 36}
            y={185}
            textAnchor="middle"
            className={T_PRIMARY}
            fontSize={14}
            fontWeight={600}
          >
            sealed
          </text>
          <text
            x={x + 90}
            y={185}
            textAnchor="middle"
            className={T_PRIMARY}
            fontSize={11.5}
            fontWeight={600}
          >
            tag
          </text>
          <text
            x={x + 52}
            y={226}
            textAnchor="middle"
            className={cn('font-mono', T_MUTED)}
            fontSize={12.5}
          >
            {NONCE_LABELS[i]}
          </text>
        </g>
      ))}
      <text x={8} y={254} className={cn('font-semibold', T_MUTED)} fontSize={13.5}>
        THE NONCE BINDS EACH CHUNK TO ITS POSITION
      </text>
      <text x={8} y={278} className={T_MAIN} fontSize={14.5}>
        Move, repeat, drop or cut off a chunk and its tag
      </text>
      <text x={8} y={298} className={T_MAIN} fontSize={14.5}>
        no longer verifies, so the download is blocked.
      </text>
    </DiagramFrame>
  );
}

/** (4) The account key hierarchy. */
export function KeyHierarchyDiagram({ className }: { className?: string }) {
  return (
    <DiagramFrame
      title="Account key hierarchy"
      description="Your password and your recovery key each derive a wrapping key. Either one unwraps the random account key. The account key wraps each drop key, and file keys come from the drop key."
      viewBox="0 0 480 430"
      className={className}
    >
      {/* Row 1: secrets */}
      <rect x={8} y={8} width={200} height={44} rx={10} className={BOX} strokeWidth={1.5} />
      <text
        x={108}
        y={36}
        textAnchor="middle"
        className={cn('font-semibold', T_MAIN)}
        fontSize={15.5}
      >
        Your password
      </text>
      <rect x={272} y={8} width={200} height={44} rx={10} className={BOX} strokeWidth={1.5} />
      <text
        x={372}
        y={36}
        textAnchor="middle"
        className={cn('font-semibold', T_MAIN)}
        fontSize={15.5}
      >
        Your recovery key
      </text>

      <ArrowDown x={108} y1={54} y2={96} />
      <ArrowDown x={372} y1={54} y2={96} />
      <text x={118} y={82} className={T_MUTED} fontSize={13}>
        Argon2id
      </text>
      <text x={382} y={82} className={T_MUTED} fontSize={13}>
        HKDF
      </text>

      {/* Row 2: derived keys */}
      <rect
        x={8}
        y={98}
        width={200}
        height={44}
        rx={10}
        className={BOX_PRIMARY}
        strokeWidth={1.5}
      />
      <text
        x={108}
        y={126}
        textAnchor="middle"
        className={cn('font-semibold', T_PRIMARY)}
        fontSize={15.5}
      >
        Wrapping key
      </text>
      <rect
        x={272}
        y={98}
        width={200}
        height={44}
        rx={10}
        className={BOX_PRIMARY}
        strokeWidth={1.5}
      />
      <text
        x={372}
        y={126}
        textAnchor="middle"
        className={cn('font-semibold', T_PRIMARY)}
        fontSize={15.5}
      >
        Wrapping key
      </text>

      <ArrowDown x={108} y1={144} y2={198} className="stroke-primary" />
      <ArrowDown x={372} y1={144} y2={198} className="stroke-primary" />
      <text x={20} y={176} className={T_MUTED} fontSize={13}>
        unwraps
      </text>
      <text x={384} y={176} className={T_MUTED} fontSize={13}>
        unwraps
      </text>

      {/* Row 3: account key */}
      <rect x={8} y={200} width={464} height={60} rx={12} className={BOX_PRIMARY} strokeWidth={2} />
      <text
        x={240}
        y={226}
        textAnchor="middle"
        className={cn('font-semibold', T_PRIMARY)}
        fontSize={16.5}
      >
        Account key
      </text>
      <text x={240} y={247} textAnchor="middle" className={T_MAIN} fontSize={13.5}>
        random, made in your browser, stored only in wrapped form
      </text>

      <ArrowDown x={240} y1={262} y2={308} />
      <text x={254} y={290} className={T_MUTED} fontSize={13}>
        wraps
      </text>

      {/* Row 4: drop key */}
      <rect x={90} y={310} width={300} height={44} rx={10} className={BOX} strokeWidth={1.5} />
      <text
        x={240}
        y={337}
        textAnchor="middle"
        className={cn('font-semibold', T_MAIN)}
        fontSize={15.5}
      >
        Drop key (one per drop)
      </text>

      <ArrowDown x={240} y1={356} y2={392} />
      <text x={254} y={378} className={T_MUTED} fontSize={13}>
        HKDF
      </text>
      <rect x={90} y={394} width={300} height={32} rx={10} className={BOX} strokeWidth={1.5} />
      <text x={240} y={415} textAnchor="middle" className={T_MAIN} fontSize={14}>
        File keys and manifest key
      </text>
    </DiagramFrame>
  );
}
