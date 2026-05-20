# Aegis Web Dashboard

Production-grade runtime observability and governance UI for the Aegis AI Agent Security Platform.

## Stack
- Vite + React 18 + TypeScript
- Tailwind CSS 3.4
- Zustand (state management)
- Framer Motion (animations)
- Vitest + Testing Library (unit tests)
- Playwright (e2e tests)

## Development

npm install
npm run dev        # Start dev server at localhost:5173
npm test           # Run unit tests
npx playwright test  # Run e2e tests (auto-starts dev server)

## Build

npm run build      # Output to dist/
npm run preview    # Preview production build

## Deploy

The output of `npm run build` is a static site deployable to any static host (Vercel, Netlify, GitHub Pages).

Vercel: Connect the repo, set root directory to `web/`, build command `npm run build`, output dir `dist`.
