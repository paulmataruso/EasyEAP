import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { LogoMark, Wordmark } from './Logo'

describe('Logo', () => {
  it('gives every copy of the mark its own gradient ids', () => {
    const { container } = render(<><LogoMark /><LogoMark /></>)
    const ids = [...container.querySelectorAll('linearGradient')].map((g) => g.id)
    expect(ids).toHaveLength(4)
    expect(new Set(ids).size).toBe(4)
    for (const svg of container.querySelectorAll('svg')) {
      const own = [...svg.querySelectorAll('linearGradient')].map((g) => `url(#${g.id})`)
      const used = [...svg.querySelectorAll('[fill^="url("]')].map((el) => el.getAttribute('fill'))
      expect(used.length).toBeGreaterThan(0)
      for (const ref of used) expect(own).toContain(ref)
    }
  })

  it('is announced once as EasyEAP', () => {
    render(<Wordmark />)
    expect(screen.queryByRole('img')).not.toBeInTheDocument()
    expect(screen.getAllByText('EasyEAP')).toHaveLength(1)
  })

  it('names a standalone mark', () => {
    render(<LogoMark />)
    expect(screen.getByRole('img', { name: 'EasyEAP' })).toBeInTheDocument()
  })
})
