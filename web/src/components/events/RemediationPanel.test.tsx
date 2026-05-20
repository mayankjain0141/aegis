import { render, screen } from '@testing-library/react'
import { RemediationPanel } from './RemediationPanel'
import { generateDenyEvent, generateAllowEvent } from '../../lib/mock/generators'

describe('RemediationPanel', () => {
  it('renders for deny events', () => {
    render(<RemediationPanel event={generateDenyEvent()} />)
    expect(screen.getByText(/allowlist/i)).toBeTruthy()
  })
  it('does not render for allow events', () => {
    const { container } = render(<RemediationPanel event={generateAllowEvent()} />)
    expect(container.firstChild).toBeNull()
  })
  it('shows copy JSON button', () => {
    render(<RemediationPanel event={generateDenyEvent()} />)
    expect(screen.getByText(/copy json/i)).toBeTruthy()
  })
  it('shows simulate button', () => {
    render(<RemediationPanel event={generateDenyEvent()} />)
    expect(screen.getByText(/simulate/i)).toBeTruthy()
  })
})
