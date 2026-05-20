import { render, screen } from '@testing-library/react'
import { StatCard } from './StatCard'

describe('StatCard', () => {
  it('renders label and value', () => {
    render(<StatCard label="Total Events" value="1,247" />)
    expect(screen.getByText('Total Events')).toBeTruthy()
    expect(screen.getByText('1,247')).toBeTruthy()
  })
  it('renders trend when provided', () => {
    render(<StatCard label="Deny Rate" value="12.3%" trend="+2%" />)
    expect(screen.getByText('+2%')).toBeTruthy()
  })
})
