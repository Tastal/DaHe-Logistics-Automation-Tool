import {
  type UIEvent,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import {
  Clipboard,
  Download,
  Pause,
  Play,
  Search,
} from "lucide-react";

import type {
  RuntimeLogEvent,
  RuntimeLogLevel,
} from "../../api/auditContracts";
import type { AppServices } from "../../app/contracts";

const MAX_VISIBLE_LOGS = 1000;

function logLine(event: RuntimeLogEvent): string {
  const time = new Date(event.createdAt).toLocaleTimeString("zh-CN", {
    hour12: false,
  });
  return `${time} ${event.level.toUpperCase().padEnd(7)} ${event.source} ${event.message}`;
}

export function RuntimeLogTerminal({ services }: { services: AppServices }) {
  const [events, setEvents] = useState<RuntimeLogEvent[]>([]);
  const [buffered, setBuffered] = useState<RuntimeLogEvent[]>([]);
  const [paused, setPaused] = useState(false);
  const [follow, setFollow] = useState(true);
  const [level, setLevel] = useState<RuntimeLogLevel | "">("");
  const [source, setSource] = useState("");
  const [search, setSearch] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const viewport = useRef<HTMLDivElement>(null);
  const pausedRef = useRef(false);
  const cursorRef = useRef<string | null>(null);

  useEffect(() => {
    pausedRef.current = paused;
  }, [paused]);

  useEffect(() => {
    let active = true;
    void services
      .loadRuntimeLogs?.({ limit: 1000 })
      .then((page) => {
        if (active && page) {
          setEvents(page.events.slice(-MAX_VISIBLE_LOGS));
          cursorRef.current = page.latestCursor;
          setLoaded(true);
        }
      })
      .catch(() => {
        if (active) {
          setMessage("运行日志加载失败。");
          setLoaded(true);
        }
      });
    return () => {
      active = false;
    };
  }, [services]);

  useEffect(() => {
    if (!loaded || !services.subscribeRuntimeLogs) return;
    return services.subscribeRuntimeLogs(cursorRef.current, (event) => {
      cursorRef.current = event.eventId;
      if (pausedRef.current) {
        setBuffered((current) => [...current, event].slice(-MAX_VISIBLE_LOGS));
        return;
      }
      setEvents((current) => {
        if (current.some((existing) => existing.eventId === event.eventId)) {
          return current;
        }
        return [...current, event].slice(-MAX_VISIBLE_LOGS);
      });
    });
  }, [loaded, services]);

  useEffect(() => {
    if (!follow || paused || !viewport.current) return;
    viewport.current.scrollTop = viewport.current.scrollHeight;
  }, [events, follow, paused]);

  const sources = useMemo(
    () => Array.from(new Set(events.map((event) => event.source))).sort(),
    [events],
  );
  const visible = useMemo(() => {
    const needle = search.trim().toLocaleLowerCase();
    return events.filter(
      (event) =>
        (!level || event.level === level) &&
        (!source || event.source === source) &&
        (!needle ||
          event.message.toLocaleLowerCase().includes(needle) ||
          event.eventCode.toLocaleLowerCase().includes(needle)),
    );
  }, [events, level, search, source]);

  const resume = () => {
    setEvents((current) => {
      const known = new Set(current.map((event) => event.eventId));
      return [
        ...current,
        ...buffered.filter((event) => !known.has(event.eventId)),
      ].slice(-MAX_VISIBLE_LOGS);
    });
    setBuffered([]);
    setPaused(false);
    setFollow(true);
  };

  const copyVisible = async () => {
    const text = visible.map(logLine).join("\n");
    try {
      await navigator.clipboard.writeText(text);
      setMessage("已复制可见日志。");
    } catch {
      setMessage("复制失败，请在日志窗口中全选并复制。");
    }
  };

  const handleScroll = (event: UIEvent<HTMLDivElement>) => {
    const element = event.currentTarget;
    const atBottom =
      element.scrollHeight - element.scrollTop - element.clientHeight < 12;
    setFollow(atBottom);
  };

  return (
    <section className="runtime-log-section" aria-labelledby="runtime-log-title">
      <header className="runtime-log-heading">
        <h3 id="runtime-log-title">后台运行日志</h3>
        <div className="runtime-log-actions">
          <button
            className="button"
            type="button"
            onClick={() => (paused ? resume() : setPaused(true))}
          >
            {paused ? (
              <Play aria-hidden="true" size={16} />
            ) : (
              <Pause aria-hidden="true" size={16} />
            )}
            {paused ? "继续" : "暂停"}
          </button>
          <button className="button" type="button" onClick={() => void copyVisible()}>
            <Clipboard aria-hidden="true" size={16} />
            复制可见日志
          </button>
          <a className="button" href="/api/v1/diagnostics/logs/export">
            <Download aria-hidden="true" size={16} />
            导出全部日志
          </a>
        </div>
      </header>
      <div className="runtime-log-filters">
        <label>
          <span>级别</span>
          <select
            value={level}
            onChange={(event) =>
              setLevel(event.target.value as RuntimeLogLevel | "")
            }
          >
            <option value="">全部</option>
            <option value="debug">调试</option>
            <option value="info">信息</option>
            <option value="warning">警告</option>
            <option value="error">错误</option>
          </select>
        </label>
        <label>
          <span>来源</span>
          <select value={source} onChange={(event) => setSource(event.target.value)}>
            <option value="">全部</option>
            {sources.map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
        </label>
        <label className="runtime-log-search">
          <Search aria-hidden="true" size={16} />
          <span className="sr-only">搜索日志</span>
          <input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="搜索日志"
          />
        </label>
        <label className="follow-toggle">
          <input
            type="checkbox"
            checked={follow}
            onChange={(event) => setFollow(event.target.checked)}
          />
          自动跟随
        </label>
      </div>
      {buffered.length > 0 ? (
        <button className="new-log-notice" type="button" onClick={resume}>
          {buffered.length} 条新日志
        </button>
      ) : null}
      {message ? (
        <p className="inline-message" role="status">
          {message}
        </p>
      ) : null}
      <div
        ref={viewport}
        className="runtime-log-terminal"
        role="log"
        aria-live="off"
        tabIndex={0}
        onScroll={handleScroll}
      >
        {visible.map((event) => (
          <div className={`runtime-log-line log-${event.level}`} key={event.eventId}>
            <time dateTime={event.createdAt}>
              {new Date(event.createdAt).toLocaleTimeString("zh-CN", {
                hour12: false,
              })}
            </time>
            <span>{event.level.toUpperCase()}</span>
            <strong>{event.source}</strong>
            <code>{event.message}</code>
          </div>
        ))}
        {visible.length === 0 ? <p>当前没有符合条件的日志。</p> : null}
      </div>
    </section>
  );
}
