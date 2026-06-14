import { useEffect, useMemo, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { useFormattedResetTime } from "../hooks/useFormattedResetTime";
import { useProviders } from "../hooks/useProviders";
import { getSettingsSnapshot, refreshProvidersIfStale } from "../lib/tauri";
import { ProviderIcon } from "../components/providers/ProviderIcon";
import { getProviderIcon } from "../components/providers/providerIcons";
import type {
  BootstrapState,
  ProviderUsageSnapshot,
  RateWindowSnapshot,
  SettingsSnapshot,
} from "../types/bridge";
import { FLOAT_BAR_CONFIG_CHANGED_EVENT } from "./api";
import "./FloatBar.css";

/**
 * A single capacity bubble in the float bar. Most providers map to exactly one
 * pill (their primary window), but some — like Antigravity, which tracks Gemini
 * and Claude/GPT model families on separate quotas — expand into several pills.
 */
interface FloatPill {
  /** Stable React key, unique across all rendered pills. */
  key: string;
  /** Icon-registry id used for the brand glyph + color. */
  iconId: string;
  /** Human label shown in the tooltip. */
  displayName: string;
  /** The usage window this bubble summarizes. */
  window: RateWindowSnapshot;
  /** Provider-level error, if the snapshot failed to fetch. */
  error: string | null;
}

/** Pick the most restrictive (exhausted first, else highest-used) window. */
function worstWindow(windows: RateWindowSnapshot[]): RateWindowSnapshot {
  return windows.reduce((worst, w) => {
    if (w.isExhausted && !worst.isExhausted) return w;
    if (!w.isExhausted && worst.isExhausted) return worst;
    return w.usedPercent > worst.usedPercent ? w : worst;
  });
}

/**
 * Expand a provider snapshot into the float-bar pills it should render.
 *
 * Antigravity multiplexes two model families behind one provider, so it gets
 * two bubbles: Gemini (its primary/secondary windows) and the non-Gemini
 * Claude & GPT models (its extra rate windows). Each bubble shows the most
 * restrictive window in its family. Every other provider maps to a single
 * pill backed by its primary window.
 */
function pillsForProvider(p: ProviderUsageSnapshot): FloatPill[] {
  if (p.providerId === "antigravity" && !p.error) {
    const geminiWindows = [p.primary, p.secondary].filter(
      (w): w is RateWindowSnapshot => w != null,
    );
    const otherWindows = (p.extraRateWindows ?? []).map((e) => e.window);
    const pills: FloatPill[] = [];
    if (geminiWindows.length > 0) {
      pills.push({
        key: `${p.providerId}:gemini`,
        iconId: "gemini",
        displayName: `${p.displayName} · Gemini`,
        window: worstWindow(geminiWindows),
        error: null,
      });
    }
    if (otherWindows.length > 0) {
      pills.push({
        key: `${p.providerId}:other`,
        iconId: "antigravity",
        displayName: `${p.displayName} · Claude & GPT`,
        window: worstWindow(otherWindows),
        error: null,
      });
    }
    if (pills.length > 0) return pills;
  }

  return [
    {
      key: p.providerId,
      iconId: p.providerId,
      displayName: p.displayName,
      window: p.primary,
      error: p.error,
    },
  ];
}

/**
 * The capacity pill shown for a single usage window.
 *
 * Color follows usage: green default, amber when remaining drops below the
 * high-usage threshold, red when remaining is below the critical threshold
 * or the window is exhausted.
 */
function ProviderPill({
  pill,
  highRemaining,
  critRemaining,
  showAsUsed,
}: {
  pill: FloatPill;
  highRemaining: number;
  critRemaining: number;
  showAsUsed: boolean;
}) {
  const { window: win, error } = pill;
  const remaining = Math.max(0, Math.min(100, win.remainingPercent));
  const used = Math.max(0, Math.min(100, win.usedPercent));
  const displayPercent = showAsUsed ? used : remaining;
  const displaySuffix = showAsUsed ? "used" : "remaining";
  const exhausted = win.isExhausted || error;
  let tone: "ok" | "warn" | "crit" = "ok";
  if (exhausted || remaining <= critRemaining) tone = "crit";
  else if (remaining <= highRemaining) tone = "warn";

  const brand = getProviderIcon(pill.iconId).brandColor;
  const label = error ? "—" : `${Math.round(displayPercent)}%`;
  const resetText = useFormattedResetTime(
    win.resetsAt,
    win.resetDescription,
    true,
  );
  const resetSuffix = resetText ? `\n${resetText}` : "";

  return (
    <div
      className={`floatbar__pill floatbar__pill--${tone}`}
      title={`${pill.displayName}: ${label} ${displaySuffix}${resetSuffix}`}
      style={{ "--brand": brand } as React.CSSProperties}
    >
      <ProviderIcon providerId={pill.iconId} size={11} />
      <span className="floatbar__pct">{label}</span>
    </div>
  );
}

/**
 * The always-on-top floating capacity bar.
 *
 * Renders a tiny strip of provider pills. Listens to the same provider
 * refresh cycle as the rest of the app via `useProviders`, and reacts to
 * setting changes (filter list, orientation) live without a reload.
 */
export default function FloatBar({ state }: { state: BootstrapState }) {
  const { providers } = useProviders({ refreshOnMount: false });

  // Mark the body so our CSS can strip the dark theme background — the
  // floatbar window is meant to be fully transparent around the pills.
  useEffect(() => {
    document.body.classList.add("floatbar-window");
    return () => {
      document.body.classList.remove("floatbar-window");
    };
  }, []);

  // The floatbar window is detached, so it doesn't share React state
  // with the Settings tab. Listen for the Rust-side config-changed event
  // and re-pull the snapshot when fired.
  const [settings, setSettings] = useState<SettingsSnapshot>(state.settings);

  // The Tauri shell has no global refresh timer — providers only update
  // when something explicitly asks for it. Drive our own tick here so the
  // bar reflects fresh data even when the tray panel is closed.
  // `refreshProvidersIfStale` is a no-op when the backend cache is fresh,
  // so this is safe to call frequently.
  useEffect(() => {
    const intervalMs = Math.max(60_000, settings.refreshIntervalSecs * 1000);
    const tick = () => {
      void refreshProvidersIfStale().catch(() => {});
    };
    tick();
    const id = setInterval(tick, intervalMs);
    return () => clearInterval(id);
  }, [settings.refreshIntervalSecs]);
  useEffect(() => {
    const unlisten = listen(FLOAT_BAR_CONFIG_CHANGED_EVENT, () => {
      void getSettingsSnapshot().then(setSettings).catch(() => {});
    });
    return () => {
      void unlisten.then((fn) => fn());
    };
  }, []);

  // Orientation flips re-lay-out the bar without recreating the window.
  const orientation: "horizontal" | "vertical" =
    settings.floatBarOrientation === "vertical" ? "vertical" : "horizontal";
  const filterIds = settings.floatBarProviderIds;
  // Expand providers into pills (Antigravity → two: Gemini + Claude/GPT) and
  // sort the bubbles themselves by usage so the busiest family leads.
  const pills = useMemo(() => {
    const enabled = new Set(settings.enabledProviders);
    let list = providers.filter((p) => enabled.has(p.providerId));
    if (filterIds && filterIds.length > 0) {
      const wanted = new Set(filterIds);
      list = list.filter((p) => wanted.has(p.providerId));
    }
    return list
      .flatMap(pillsForProvider)
      .sort((a, b) => b.window.usedPercent - a.window.usedPercent);
  }, [providers, settings.enabledProviders, filterIds]);

  // Resize the window to fit content when the visible set or orientation changes.
  useEffect(() => {
    const win = getCurrentWindow();
    const el = document.querySelector<HTMLElement>(".floatbar");
    if (!el) return;
    requestAnimationFrame(() => {
      const rect = el.getBoundingClientRect();
      const padding = 8;
      const w = Math.ceil(rect.width + padding);
      const h = Math.ceil(rect.height + padding);
      void Promise.resolve(
        win.setSize({ type: "Logical", width: w, height: h } as never),
      ).catch(() => {});
    });
  }, [pills.length, orientation]);

  const highRemaining = 100 - settings.highUsageThreshold;
  const critRemaining = 100 - settings.criticalUsageThreshold;
  const opacityFraction = Math.max(0.3, Math.min(1, settings.floatBarOpacity / 100));

  return (
    <div
      className={`floatbar floatbar--${orientation}${settings.floatBarDarkText ? " floatbar--light-bg" : ""}`}
      data-tauri-drag-region
      style={{ opacity: opacityFraction }}
    >
      <div className="floatbar__handle" data-tauri-drag-region aria-hidden />
      {pills.length === 0 ? (
        <div className="floatbar__empty">No providers</div>
      ) : (
        pills.map((p) => (
          <ProviderPill
            key={p.key}
            pill={p}
            highRemaining={highRemaining}
            critRemaining={critRemaining}
            showAsUsed={settings.showAsUsed}
          />
        ))
      )}
    </div>
  );
}
