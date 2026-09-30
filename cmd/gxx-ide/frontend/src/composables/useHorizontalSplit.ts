import { onBeforeUnmount, ref, type Ref } from 'vue'

export interface SplitPaneOptions {
  /** localStorage key for persisting width */
  storageKey?: string
  defaultWidth: number
  minWidth: number
  /** reserved width for panels on the right (result panel + handles) */
  reservedRight: number
  /** min width for the flex panel to the right of the handle */
  minFlexWidth: number
}

export function useHorizontalSplit(
  containerRef: Ref<HTMLElement | null>,
  options: SplitPaneOptions,
) {
  const stored = options.storageKey ? localStorage.getItem(options.storageKey) : null
  const parsed = stored ? Number(stored) : NaN
  const leftWidth = ref(Number.isFinite(parsed) ? parsed : options.defaultWidth)
  const dragging = ref(false)

  function clampWidth(next: number): number {
    const el = containerRef.value
    if (!el) return Math.max(options.minWidth, next)
    const max = el.clientWidth - options.reservedRight - options.minFlexWidth
    return Math.max(options.minWidth, Math.min(max, next))
  }

  function persist() {
    if (options.storageKey) {
      localStorage.setItem(options.storageKey, String(leftWidth.value))
    }
  }

  let stopDragging: (() => void) | undefined

  function onResizeStart(e: MouseEvent) {
    stopDragging?.()
    const previousCursor = document.body.style.cursor
    const previousSelection = document.body.style.userSelect
    const startX = e.clientX
    const startW = leftWidth.value
    dragging.value = true

    const onMove = (ev: MouseEvent) => {
      leftWidth.value = clampWidth(startW + ev.clientX - startX)
    }

    const onUp = () => {
      dragging.value = false
      document.removeEventListener('mousemove', onMove)
      document.removeEventListener('mouseup', onUp)
      document.body.style.cursor = previousCursor
      document.body.style.userSelect = previousSelection
      stopDragging = undefined
      persist()
    }

    stopDragging = onUp
    document.body.style.cursor = 'col-resize'
    document.body.style.userSelect = 'none'
    document.addEventListener('mousemove', onMove)
    document.addEventListener('mouseup', onUp)
  }

  function resetWidth() {
    leftWidth.value = options.defaultWidth
    persist()
  }

  onBeforeUnmount(() => {
    stopDragging?.()
  })

  return { leftWidth, dragging, onResizeStart, clampWidth, resetWidth }
}
