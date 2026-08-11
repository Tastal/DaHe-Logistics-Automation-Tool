import { Maximize2, Minus, Plus, RotateCcw, RotateCw, X } from "lucide-react";
import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import { createPortal } from "react-dom";

import { Tooltip } from "./Tooltip";

export function ImageViewer({
  url,
  label,
  onClose,
}: {
  url: string;
  label: string;
  onClose: () => void;
}) {
  const [rotation, setRotation] = useState(0);
  const [scale, setScale] = useState(1);
  useEffect(() => {
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
      if (event.key === "ArrowLeft") setRotation((value) => value - 90);
      if (event.key === "ArrowRight") setRotation((value) => value + 90);
      if (event.key === "+" || event.key === "=") setScale((value) => Math.min(4, value + 0.2));
      if (event.key === "-") setScale((value) => Math.max(0.4, value - 0.2));
    };
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("keydown", onKey);
      document.body.style.overflow = previousOverflow;
    };
  }, [onClose]);
  const tool = (text: string, icon: ReactNode, action: () => void) => (
    <Tooltip content={text}>
      <button className="image-tool" type="button" aria-label={text} onClick={action}>{icon}</button>
    </Tooltip>
  );
  return createPortal(
    <div className="image-viewer" role="dialog" aria-modal="true" aria-label={label}>
      <div className="image-viewer-toolbar">
        {tool("向左旋转", <RotateCcw aria-hidden="true" size={20} />, () => setRotation((value) => value - 90))}
        {tool("向右旋转", <RotateCw aria-hidden="true" size={20} />, () => setRotation((value) => value + 90))}
        {tool("放大", <Plus aria-hidden="true" size={20} />, () => setScale((value) => Math.min(4, value + 0.2)))}
        {tool("缩小", <Minus aria-hidden="true" size={20} />, () => setScale((value) => Math.max(0.4, value - 0.2)))}
        {tool("适合窗口", <Maximize2 aria-hidden="true" size={20} />, () => { setRotation(0); setScale(1); })}
        {tool("关闭", <X aria-hidden="true" size={20} />, onClose)}
      </div>
      <div className="image-viewer-canvas" onClick={onClose}>
        <img src={url} alt={label} style={{ transform: `rotate(${rotation}deg) scale(${scale})` }} onClick={(event) => event.stopPropagation()} />
      </div>
    </div>,
    document.body,
  );
}
