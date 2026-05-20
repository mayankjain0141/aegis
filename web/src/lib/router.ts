export type Route = 'runtime' | 'policies' | 'posture'

export function getRoute(): Route {
  const hash = window.location.hash
  if (hash.startsWith('#/policies')) return 'policies'
  if (hash.startsWith('#/posture')) return 'posture'
  return 'runtime'
}

export function getSelectedEventId(): string | null {
  const match = window.location.hash.match(/#\/events\/(.+)/)
  return match ? match[1] : null
}

export function navigateTo(route: Route) {
  window.location.hash = `#/${route}`
}

export function selectEventInUrl(id: string | null) {
  if (id) {
    window.location.hash = `#/events/${id}`
  } else {
    window.location.hash = '#/runtime'
  }
}
