export function Skeleton({ className = '' }: { className?: string }) {
  return (
    <div className={`bg-raised animate-pulse rounded ${className}`} />
  )
}
