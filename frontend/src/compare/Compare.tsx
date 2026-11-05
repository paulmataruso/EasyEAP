import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router'
import { ExternalLink, PanelRightOpen, PanelRightClose } from 'lucide-react'
import { CONCEPTS } from '@/concepts/registry'
import { SCREENS, type ScreenId } from '@/concepts/contract'
import { LogoMark } from '@/ui/Logo'
import { cn } from '@/ui/lib'
import { CONCEPT_NOTES } from './notes'

/** Side-by-side switcher for the six design concepts. Each concept renders in an isolated iframe. */
export function Compare() {
  const [params, setParams] = useSearchParams()
  const concept = (params.get('concept') ?? 'a') as (typeof CONCEPTS)[number]['id']
  const screen = (params.get('screen') ?? 'dashboard') as ScreenId
  const [notesOpen, setNotesOpen] = useState(true)
  const set = (next: { concept?: string; screen?: string }) =>
    setParams({ concept: next.concept ?? concept, screen: next.screen ?? screen }, { replace: true })

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLInputElement || e.metaKey || e.ctrlKey || e.altKey) return
      const idx = CONCEPTS.findIndex((c) => c.id === concept)
      if (/^[1-6]$/.test(e.key)) set({ concept: CONCEPTS[Number(e.key) - 1].id })
      if (e.key === 'ArrowRight') set({ concept: CONCEPTS[(idx + 1) % CONCEPTS.length].id })
      if (e.key === 'ArrowLeft') set({ concept: CONCEPTS[(idx + CONCEPTS.length - 1) % CONCEPTS.length].id })
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  })

  const src = `${window.location.pathname}?frame=1#/c/${concept}/${screen}`
  const notes = CONCEPT_NOTES[concept]
  const meta = CONCEPTS.find((c) => c.id === concept)!

  return (
    <div className="flex h-full flex-col bg-[#07090d] font-[system-ui] text-[#dfe4ec]">
      <header className="flex flex-wrap items-center gap-x-6 gap-y-2 border-b border-white/10 px-4 py-2.5">
        <div className="flex items-center gap-2 text-[15px] font-semibold text-white">
          <LogoMark className="size-6 text-sky-300" />
          EasyEAP <span className="font-normal text-[#9aa4b2]">design concepts</span>
        </div>
        <nav aria-label="Concepts" className="flex flex-wrap gap-1">
          {CONCEPTS.map((c, i) => (
            <button
              key={c.id}
              onClick={() => set({ concept: c.id })}
              aria-pressed={c.id === concept}
              className={cn(
                'rounded-md px-2.5 py-1.5 text-left text-[13px] leading-tight transition-colors focus-visible:outline-2 focus-visible:outline-sky-300',
                c.id === concept ? 'bg-white/12 text-white' : 'text-[#aab3c0] hover:bg-white/6 hover:text-white',
              )}
            >
              <span className="font-semibold">{c.id.toUpperCase()}</span> {c.name}
              <span className="block text-[11px] text-[#8b95a3]">
                {c.skill} · key {i + 1}
              </span>
            </button>
          ))}
        </nav>
        <div className="ml-auto flex items-center gap-2">
          <a href={src} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1.5 rounded-md px-2.5 py-1.5 text-[13px] text-[#aab3c0] hover:bg-white/6 hover:text-white">
            <ExternalLink className="size-4" aria-hidden /> Full screen
          </a>
          <button onClick={() => setNotesOpen((o) => !o)} aria-expanded={notesOpen} className="inline-flex items-center gap-1.5 rounded-md px-2.5 py-1.5 text-[13px] text-[#aab3c0] hover:bg-white/6 hover:text-white">
            {notesOpen ? <PanelRightClose className="size-4" aria-hidden /> : <PanelRightOpen className="size-4" aria-hidden />} Notes
          </button>
        </div>
      </header>
      <nav aria-label="Screens" className="flex gap-1 overflow-x-auto border-b border-white/10 px-4 py-1.5">
        {SCREENS.map((s) => (
          <button
            key={s.id}
            onClick={() => set({ screen: s.id })}
            aria-current={s.id === screen ? 'page' : undefined}
            className={cn('whitespace-nowrap rounded px-2.5 py-1 text-[13px]', s.id === screen ? 'bg-sky-300/15 text-sky-200' : 'text-[#aab3c0] hover:text-white')}
          >
            {s.label}
          </button>
        ))}
        <span className="ml-auto self-center whitespace-nowrap pl-4 text-[11px] text-[#8b95a3]">Synthetic sample data · ←/→ or 1–6 to switch</span>
      </nav>
      <div className="flex min-h-0 flex-1">
        <iframe key={concept} title={`Concept ${concept.toUpperCase()}: ${meta.name}`} src={src} className="min-w-0 flex-1 border-0 bg-black" />
        {notesOpen && (
          <aside className="w-[340px] shrink-0 overflow-y-auto border-l border-white/10 p-5 text-[13.5px] leading-relaxed" aria-label="Concept notes">
            <h2 className="text-[17px] font-semibold text-white">
              {concept.toUpperCase()} · {meta.name}
            </h2>
            <p className="mt-0.5 text-[12px] text-[#8b95a3]">Produced with {meta.skill}</p>
            <p className="mt-3 text-[#c5ccd6]">{notes.thesis}</p>
            {notes.score && <p className="mt-3 text-[#c5ccd6]">Impeccable critique: <strong className="text-white">{notes.score}</strong></p>}
            <h3 className="mt-5 font-semibold text-white">Strengths</h3>
            <ul className="mt-1.5 list-disc space-y-1 pl-4 text-[#c5ccd6]">{notes.strengths.map((s) => <li key={s}>{s}</li>)}</ul>
            <h3 className="mt-5 font-semibold text-white">Weaknesses</h3>
            <ul className="mt-1.5 list-disc space-y-1 pl-4 text-[#c5ccd6]">{notes.weaknesses.map((s) => <li key={s}>{s}</li>)}</ul>
            <h3 className="mt-5 font-semibold text-white">Provenance</h3>
            <p className="mt-1.5 text-[#c5ccd6]">{notes.provenance}</p>
          </aside>
        )}
      </div>
    </div>
  )
}
