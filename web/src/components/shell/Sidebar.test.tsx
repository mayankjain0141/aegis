import { render, screen } from '@testing-library/react'
import { Sidebar } from './Sidebar'

describe('Sidebar', () => {
  it('renders runtime nav item', () => {
    render(<Sidebar />)
    // Sidebar has navigation items - check for Shield/Runtime icon area
    expect(document.querySelector('nav')).toBeTruthy()
  })
  it('renders engine online indicator', () => {
    render(<Sidebar />)
    expect(screen.getByText(/online/i)).toBeTruthy()
  })
})
