import { render } from '@testing-library/react'
import App from './App'

describe('App', () => {
  it('renders without crashing', () => {
    render(<App />)
    expect(document.body).toBeTruthy()
  })

  it('has the correct dark background class', () => {
    const { container } = render(<App />)
    const root = container.firstChild as HTMLElement
    expect(root.className).toContain('bg-base')
  })
})
