import type { ReactNode } from 'react'

/** Screen title row: h1 + one line of context, actions on the right. No kicker above the title. */
export function PageHeader({ title, context, actions, children }: { title: ReactNode; context?: ReactNode; actions?: ReactNode; children?: ReactNode }) {
  return (
    <div className="mb-3.5 flex flex-wrap items-center gap-x-4 gap-y-2">
      <div className="min-w-0">
        <h1 className="text-[21px] leading-tight font-semibold tracking-[-0.005em] text-[var(--b-text)]">{title}</h1>
        {context && <p className="b-t2 mt-0.5 text-[13px]">{context}</p>}
      </div>
      {children}
      {actions && <div className="ml-auto flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  )
}
