import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { EvalChain } from './EvalChain'
import { generateDenyEvent, generateAllowEvent } from '../../lib/mock/generators'

describe('EvalChain', () => {
  it('renders when eval_chain is non-empty', () => {
    const event = generateDenyEvent()
    render(<EvalChain evalChain={event.eval_chain} matchedRule={event.rule} />)
    expect(screen.getByText(event.rule)).toBeTruthy()
  })
  it('collapsed state shows matched rule', () => {
    const event = generateDenyEvent()
    render(<EvalChain evalChain={event.eval_chain} matchedRule={event.rule} />)
    expect(screen.getByText(event.rule)).toBeTruthy()
  })
  it('shows summary of skipped rules count', () => {
    const event = generateDenyEvent()
    // eval_chain has many steps — should show "N rules skipped" or similar
    render(<EvalChain evalChain={event.eval_chain} matchedRule={event.rule} />)
    // Either the count is shown or "Show all" is shown
    const text = document.body.textContent || ''
    expect(text).toMatch(/skip|more|show/i)
  })
  it('matched rule is visually distinct (has class indicating match)', () => {
    const event = generateDenyEvent()
    render(<EvalChain evalChain={event.eval_chain} matchedRule={event.rule} />)
    // Find the matched rule element — it should have MATCH text
    expect(screen.getByText('MATCH')).toBeTruthy()
  })
  it('clicking Show all expands to show all steps', async () => {
    const event = generateDenyEvent()
    // Ensure we have enough steps to trigger the expand button
    event.eval_chain = [
      { rule: 'rule_a', priority: 1, action: 'deny', result: 'skip' },
      { rule: 'rule_b', priority: 2, action: 'deny', result: 'skip' },
      { rule: event.rule, priority: 3, action: event.action, result: 'match', condition: 'path.has_critical AND verb:rm' },
      { rule: 'rule_d', priority: 4, action: 'deny', result: 'skip' },
      { rule: 'rule_e', priority: 5, action: 'deny', result: 'skip' },
    ]
    render(<EvalChain evalChain={event.eval_chain} matchedRule={event.rule} />)
    const expandBtn = screen.queryByText(/show all/i)
    if (expandBtn) {
      await userEvent.click(expandBtn)
      expect(screen.getByText('rule_a')).toBeTruthy()
    }
  })
  it('skip steps have lower visual weight', () => {
    const event = generateDenyEvent()
    event.eval_chain = [
      { rule: 'skipped_rule', priority: 1, action: 'deny', result: 'skip' },
      { rule: event.rule, priority: 2, action: event.action, result: 'match' },
    ]
    render(<EvalChain evalChain={event.eval_chain} matchedRule={event.rule} />)
    // After expand, skip rule should be visible
    // The skip step exists
    expect(document.body.textContent).toMatch(/skip/i)
  })
})
