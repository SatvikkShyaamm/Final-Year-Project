/**
 * Standard "not built yet" panel used by every admin page stub, so the
 * dashboard's navigation and layout are real and clickable in Module 1
 * without pretending any module 5-9 functionality already exists.
 */
export function PlaceholderCard({
  title,
  module,
  description,
}: {
  title: string
  module: string
  description: string
}) {
  return (
    <div className="rounded-xl border border-dashed border-[color:var(--color-border)] bg-[color:var(--color-surface)] p-8 text-center">
      <h2 className="text-lg font-semibold text-[color:var(--color-text)]">{title}</h2>
      <p className="mt-2 text-sm text-[color:var(--color-text-muted)]">{description}</p>
      <span className="mt-4 inline-block rounded-full border border-[color:var(--color-border)] px-3 py-1 text-xs font-medium text-[color:var(--color-text-muted)]">
        Planned for {module}
      </span>
    </div>
  )
}
