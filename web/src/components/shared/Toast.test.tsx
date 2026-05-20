import { render, screen, act } from '@testing-library/react'
import { Toast } from './Toast'

describe('Toast', () => {
  it('renders message when visible', () => {
    render(<Toast message="Copied!" visible={true} />)
    expect(screen.getByText('Copied!')).toBeTruthy()
  })
  it('does not render when not visible', () => {
    render(<Toast message="Copied!" visible={false} />)
    expect(screen.queryByText('Copied!')).toBeNull()
  })
})
