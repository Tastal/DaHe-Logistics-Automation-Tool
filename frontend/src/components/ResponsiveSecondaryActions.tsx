import { MoreHorizontal } from "lucide-react";
import { type ReactNode, useEffect, useState } from "react";

const compactQuery = "(max-width: 999px)";

function useCompactActions(): boolean {
  const [compact, setCompact] = useState(() =>
    typeof window !== "undefined" && typeof window.matchMedia === "function"
      ? window.matchMedia(compactQuery).matches
      : false,
  );

  useEffect(() => {
    if (typeof window.matchMedia !== "function") return undefined;
    const media = window.matchMedia(compactQuery);
    const update = () => setCompact(media.matches);
    update();
    media.addEventListener("change", update);
    return () => media.removeEventListener("change", update);
  }, []);

  return compact;
}

export function ResponsiveSecondaryActions({ children }: { children: ReactNode }) {
  const compact = useCompactActions();
  if (!compact) return <div className="business-secondary-actions">{children}</div>;
  return (
    <details className="business-more-actions">
      <summary className="button" role="button">
        <MoreHorizontal aria-hidden="true" size={17} />更多
      </summary>
      <div className="business-more-panel">{children}</div>
    </details>
  );
}
