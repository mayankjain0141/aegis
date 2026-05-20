import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { PlaygroundInput } from './PlaygroundInput'

describe('PlaygroundInput', () => {
  it('renders input field with placeholder', () => {
    render(<PlaygroundInput onEvaluate={() => {}} />)
    expect(screen.getByPlaceholderText(/command/i)).toBeTruthy()
  })
  it('renders evaluate button', () => {
    render(<PlaygroundInput onEvaluate={() => {}} />)
    expect(screen.getByRole('button', { name: /evaluate/i })).toBeTruthy()
  })
  it('calls onEvaluate with input value when button clicked', async () => {
    const onEvaluate = vi.fn()
    render(<PlaygroundInput onEvaluate={onEvaluate} />)
    await userEvent.type(screen.getByRole('textbox'), 'rm -rf /')
    await userEvent.click(screen.getByRole('button', { name: /evaluate/i }))
    expect(onEvaluate).toHaveBeenCalledWith('rm -rf /')
  })
  it('calls onEvaluate on Enter key', async () => {
    const onEvaluate = vi.fn()
    render(<PlaygroundInput onEvaluate={onEvaluate} />)
    await userEvent.type(screen.getByRole('textbox'), 'git status{Enter}')
    expect(onEvaluate).toHaveBeenCalledWith('git status')
  })
  it('does not call onEvaluate for empty input', async () => {
    const onEvaluate = vi.fn()
    render(<PlaygroundInput onEvaluate={() => {}} />)
    await userEvent.click(screen.getByRole('button', { name: /evaluate/i }))
    expect(onEvaluate).not.toHaveBeenCalled()
  })
  it('shows preset buttons', () => {
    render(<PlaygroundInput onEvaluate={() => {}} />)
    expect(screen.getByText(/git status/)).toBeTruthy()
  })
  it('clicking preset populates input', async () => {
    const onEvaluate = vi.fn()
    render(<PlaygroundInput onEvaluate={onEvaluate} />)
    await userEvent.click(screen.getByText(/git status/))
    // Input should now have 'git status' value
    const input = screen.getByRole('textbox') as HTMLInputElement
    expect(input.value).toBe('git status')
  })
})
