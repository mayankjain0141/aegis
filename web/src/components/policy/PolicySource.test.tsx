import { render, screen } from '@testing-library/react'
import { PolicySource } from './PolicySource'

describe('PolicySource', () => {
  it('shows file and line number', () => {
    render(<PolicySource file="policies/phase1-deny.yaml" line={12} snippet="action: deny" condition="path.has_critical" />)
    expect(screen.getByText(/phase1-deny\.yaml/)).toBeTruthy()
    expect(screen.getByText(/12/)).toBeTruthy()
  })
  it('shows condition expression', () => {
    render(<PolicySource file="policies/phase1-deny.yaml" line={12} snippet="" condition="path.has_critical AND verb:rm" />)
    expect(screen.getByText(/path\.has_critical/)).toBeTruthy()
  })
})
