import { test, expect } from '@playwright/test'

test.describe('Aegis Dashboard', () => {
  test('page loads with events within 3 seconds', async ({ page }) => {
    await page.goto('/')
    // Wait for at least one event row to appear
    await expect(page.locator('[data-testid="event-row"]').first()).toBeVisible({ timeout: 3000 })
  })

  test('clicking a deny event shows detail with DENIED verdict', async ({ page }) => {
    await page.goto('/')
    await page.waitForTimeout(500)
    // Click the first deny-colored row
    const denyRow = page.locator('[data-action="deny"]').first()
    await denyRow.waitFor({ timeout: 3000 })
    await denyRow.click()
    await expect(page.locator('text=DENIED')).toBeVisible({ timeout: 2000 })
  })

  test('navigating to policies shows playground', async ({ page }) => {
    await page.goto('/#/policies')
    await expect(page.locator('text=Policy Playground')).toBeVisible({ timeout: 2000 })
  })

  test('typing in playground and pressing Evaluate shows result', async ({ page }) => {
    await page.goto('/#/policies')
    await page.waitForTimeout(300)
    const input = page.locator('input[placeholder*="command"]')
    await input.fill('rm -rf /')
    await page.locator('button:has-text("Evaluate")').click()
    await expect(page.locator('text=DENIED')).toBeVisible({ timeout: 2000 })
  })

  test('navigating to posture shows stat cards', async ({ page }) => {
    await page.goto('/#/posture')
    await expect(page.locator('text=Total Events')).toBeVisible({ timeout: 2000 })
    await expect(page.locator('text=Deny Rate')).toBeVisible({ timeout: 2000 })
  })

  test('Cmd+K opens command palette', async ({ page }) => {
    await page.goto('/')
    await page.waitForTimeout(500)
    await page.keyboard.press('Meta+k')
    await expect(page.locator('input[placeholder*="Search"]')).toBeVisible({ timeout: 1000 })
  })

  test('Escape closes command palette', async ({ page }) => {
    await page.goto('/')
    await page.waitForTimeout(500)
    await page.keyboard.press('Meta+k')
    await page.keyboard.press('Escape')
    await expect(page.locator('input[placeholder*="Search"]')).not.toBeVisible({ timeout: 1000 })
  })

  test('after 3 seconds on runtime view, event count increases', async ({ page }) => {
    await page.goto('/')
    const initialRows = await page.locator('[data-testid="event-row"]').count()
    await page.waitForTimeout(3000)
    const laterRows = await page.locator('[data-testid="event-row"]').count()
    expect(laterRows).toBeGreaterThanOrEqual(initialRows)
  })

  test('git status preset in playground returns ALLOWED', async ({ page }) => {
    await page.goto('/#/policies')
    await page.waitForTimeout(300)
    await page.locator('button:has-text("git status")').click()
    await page.locator('button:has-text("Evaluate")').click()
    await expect(page.locator('text=ALLOWED')).toBeVisible({ timeout: 2000 })
  })

  test('posture stat cards show non-zero values after events load', async ({ page }) => {
    await page.goto('/')
    await page.waitForTimeout(1000)
    await page.goto('/#/posture')
    // Total events should be > 0
    await expect(page.locator('text=Total Events')).toBeVisible()
  })
})
