import { render } from '@testing-library/react'
import { Badge } from './Badge'

describe('Badge', () => {
  it('renders deny badge with red class', () => {
    const { container } = render(<Badge action="deny" />)
    expect(container.firstChild).toHaveClass('text-deny')
  })
  it('renders allow badge with green class', () => {
    const { container } = render(<Badge action="allow" />)
    expect(container.firstChild).toHaveClass('text-allow')
  })
  it('renders escalate badge with amber class', () => {
    const { container } = render(<Badge action="escalate" />)
    expect(container.firstChild).toHaveClass('text-escalate')
  })
})
