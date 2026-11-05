import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { ErrorBoundary } from './ErrorBoundary'

function Boom(): never {
  throw new Error('Cannot read properties of undefined')
}

describe('ErrorBoundary', () => {
  it('replaces a crashed screen with an explanation and recovers on navigation', () => {
    const quiet = vi.spyOn(console, 'error').mockImplementation(() => {})
    const { rerender } = render(<ErrorBoundary resetKey="/t/1/directory"><Boom /></ErrorBoundary>)
    expect(screen.getByRole('alert')).toHaveTextContent('This page ran into a problem')
    expect(screen.getByText('Cannot read properties of undefined')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Reload/ })).toBeInTheDocument()
    rerender(<ErrorBoundary resetKey="/t/1/users"><p>Users</p></ErrorBoundary>)
    expect(screen.getByText('Users')).toBeInTheDocument()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    quiet.mockRestore()
  })
})
