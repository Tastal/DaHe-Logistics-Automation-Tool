import {
  type ReactElement,
  type ReactNode,
  cloneElement,
  useId,
  useLayoutEffect,
  useRef,
  useState,
} from "react";
import { createPortal } from "react-dom";

export function Tooltip({
  children,
  content,
  disabledControl = false,
}: {
  children: ReactElement;
  content: ReactNode;
  disabledControl?: boolean;
}) {
  const id = useId();
  const anchor = useRef<HTMLSpanElement>(null);
  const tooltip = useRef<HTMLSpanElement>(null);
  const [open, setOpen] = useState(false);
  const [position, setPosition] = useState({ left: 0, top: 0, ready: false });

  useLayoutEffect(() => {
    if (!open) return;
    const place = () => {
      const rect = anchor.current?.getBoundingClientRect();
      const tip = tooltip.current?.getBoundingClientRect();
      if (!rect || !tip) return;
      const gap = 8;
      const edge = 8;
      const centered = rect.left + rect.width / 2 - tip.width / 2;
      const left = Math.max(edge, Math.min(centered, window.innerWidth - tip.width - edge));
      const below = rect.bottom + gap;
      const top = below + tip.height <= window.innerHeight - edge
        ? below
        : Math.max(edge, rect.top - tip.height - gap);
      setPosition({
        left,
        top,
        ready: true,
      });
    };
    const frame = window.requestAnimationFrame(place);
    window.addEventListener("resize", place);
    window.addEventListener("scroll", place, true);
    const close = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    document.addEventListener("keydown", close);
    return () => {
      window.cancelAnimationFrame(frame);
      window.removeEventListener("resize", place);
      window.removeEventListener("scroll", place, true);
      document.removeEventListener("keydown", close);
    };
  }, [open]);

  const child = cloneElement(children, {
    "aria-describedby": open ? id : undefined,
  } as Record<string, unknown>);

  return (
    <>
      <span
        ref={anchor}
        className="tooltip-anchor"
        tabIndex={disabledControl ? 0 : undefined}
        onMouseEnter={() => setOpen(true)}
        onMouseLeave={() => setOpen(false)}
        onFocusCapture={() => setOpen(true)}
        onBlurCapture={() => setOpen(false)}
      >
        {child}
      </span>
      {open
        ? createPortal(
            <span
              ref={tooltip}
              id={id}
              role="tooltip"
              className="app-tooltip"
              style={{
                left: position.left,
                top: position.top,
                visibility: position.ready ? "visible" : "hidden",
              }}
            >
              {content}
            </span>,
            document.body,
          )
        : null}
    </>
  );
}
