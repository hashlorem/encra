import { useCallback, useLayoutEffect, useRef, useState, type ReactNode } from "react";

interface VirtualListProps<T> {
  items: T[];
  getKey: (item: T) => string;
  renderRow: (item: T) => ReactNode;
  className?: string;
  /** Below this many items every row renders, with the usual entrance. */
  threshold?: number;
  /** Rows kept rendered above and below the visible ones. */
  overscan?: number;
}

/** The nearest ancestor that scrolls vertically. */
function scrollParent(node: HTMLElement | null): HTMLElement | null {
  for (let el = node?.parentElement ?? null; el; el = el.parentElement) {
    const { overflowY } = getComputedStyle(el);
    if (overflowY === "auto" || overflowY === "scroll") return el;
  }
  return null;
}

/**
 * A list that renders only the rows in view once it is long (the design
 * contract's "virtualise past ~200 rows"). Rows must share one height; it is
 * measured from the first row, so density changes need no code. Spacer
 * heights are set through the CSSOM, since the production CSP blocks inline
 * style attributes.
 */
export function VirtualList<T>({ items, getKey, renderRow, className, threshold = 200, overscan = 8 }: VirtualListProps<T>) {
  const virtual = items.length > threshold;
  const listRef = useRef<HTMLUListElement>(null);
  const topRef = useRef<HTMLLIElement>(null);
  const bottomRef = useRef<HTMLLIElement>(null);
  const rowHeight = useRef(56);
  const [range, setRange] = useState({ start: 0, end: Math.min(items.length, 40) });

  const update = useCallback(() => {
    const list = listRef.current;
    const scroller = scrollParent(list);
    if (!list || !scroller) return;
    const firstRow = list.querySelector<HTMLElement>("li[data-row]");
    if (firstRow && firstRow.offsetHeight > 0) rowHeight.current = firstRow.offsetHeight;
    const height = rowHeight.current;
    const listTop = list.getBoundingClientRect().top - scroller.getBoundingClientRect().top + scroller.scrollTop;
    const visibleTop = scroller.scrollTop - listTop;
    const start = Math.max(0, Math.floor(visibleTop / height) - overscan);
    const end = Math.min(items.length, Math.ceil((visibleTop + scroller.clientHeight) / height) + overscan);
    setRange((current) => (current.start === start && current.end === end ? current : { start, end }));
  }, [items.length, overscan]);

  useLayoutEffect(() => {
    if (!virtual) return;
    const scroller = scrollParent(listRef.current);
    if (!scroller) return;
    update();
    scroller.addEventListener("scroll", update, { passive: true });
    const observer = new ResizeObserver(update);
    observer.observe(scroller);
    return () => {
      scroller.removeEventListener("scroll", update);
      observer.disconnect();
    };
  }, [virtual, update]);

  useLayoutEffect(() => {
    if (!virtual) return;
    if (topRef.current) topRef.current.style.height = `${range.start * rowHeight.current}px`;
    if (bottomRef.current) bottomRef.current.style.height = `${(items.length - range.end) * rowHeight.current}px`;
  }, [virtual, range, items.length]);

  if (!virtual) {
    return (
      <ul className={`${className ?? ""} stagger`}>
        {items.map((item) => (
          <li key={getKey(item)}>{renderRow(item)}</li>
        ))}
      </ul>
    );
  }

  return (
    <ul ref={listRef} className={`${className ?? ""} is-virtual`}>
      <li ref={topRef} aria-hidden="true" className="virtual-spacer" />
      {items.slice(range.start, range.end).map((item) => (
        <li key={getKey(item)} data-row="">
          {renderRow(item)}
        </li>
      ))}
      <li ref={bottomRef} aria-hidden="true" className="virtual-spacer" />
    </ul>
  );
}
