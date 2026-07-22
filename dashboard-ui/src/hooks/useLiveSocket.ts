import { useEffect, useRef, useState } from "react";
import { getToken } from "../api/client";

const API_BASE = (import.meta.env.VITE_API_BASE_URL ?? "").replace(/\/$/, "");

function wsUrl(path: string): string {
  if (API_BASE) {
    const url = new URL(API_BASE);
    const protocol = url.protocol === "https:" ? "wss:" : "ws:";
    return `${protocol}//${url.host}${path}`;
  }
  const protocol = window.location.protocol === "https:" ? "wss" : "ws";
  return `${protocol}://${window.location.host}${path}`;
}

export function useLiveSocket(onRefresh: () => void, enabled: boolean) {
  const [live, setLive] = useState(false);
  const onRefreshRef = useRef(onRefresh);
  onRefreshRef.current = onRefresh;

  useEffect(() => {
    if (!enabled || !getToken()) {
      setLive(false);
      return;
    }

    const socket = new WebSocket(wsUrl("/api/ws/live"));
    socket.onopen = () => setLive(true);
    socket.onclose = () => setLive(false);
    socket.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        if (payload.type === "event" || payload.type === "agent" || payload.type === "refresh") {
          onRefreshRef.current();
        }
      } catch {
        onRefreshRef.current();
      }
    };
    const ping = window.setInterval(() => {
      if (socket.readyState === WebSocket.OPEN) socket.send("ping");
    }, 15000);
    return () => {
      window.clearInterval(ping);
      socket.close();
    };
  }, [enabled]);

  return live;
}
