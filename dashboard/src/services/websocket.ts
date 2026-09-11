import { Incident, SensorCapabilities } from '../types';

export interface WebSocketCallbacks {
  onSnapshot: (incidents: Incident[], capabilities?: SensorCapabilities) => void;
  onBatch: (incidents: Incident[]) => void;
  onStatusChange: (connected: boolean) => void;
}

export class IncidentWebSocketClient {
  private ws: WebSocket | null = null;
  private url: string;
  private callbacks: WebSocketCallbacks;
  private shouldReconnect = true;
  private reconnectTimer: number | null = null;
  private pingTimer: number | null = null;
  private reconnectAttempts = 0;

  constructor(callbacks: WebSocketCallbacks, customUrl?: string) {
    this.callbacks = callbacks;
    if (customUrl) {
      this.url = customUrl;
    } else {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const host = window.location.host;
      this.url = `${protocol}//${host}/ws/incidents`;
    }
  }

  public connect(): void {
    this.shouldReconnect = true;
    this.cleanup();

    try {
      this.ws = new WebSocket(this.url);

      this.ws.onopen = () => {
        this.reconnectAttempts = 0;
        this.callbacks.onStatusChange(true);
        this.startPing();
      };

      this.ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type === 'snapshot') {
            this.callbacks.onSnapshot(data.incidents || [], data.capabilities);
          } else if (data.type === 'incident_batch') {
            this.callbacks.onBatch(data.incidents || []);
          }
        } catch {
          // Ignored non-json or ping responses
        }
      };

      this.ws.onclose = () => {
        this.callbacks.onStatusChange(false);
        this.scheduleReconnect();
      };

      this.ws.onerror = () => {
        this.callbacks.onStatusChange(false);
      };
    } catch {
      this.callbacks.onStatusChange(false);
      this.scheduleReconnect();
    }
  }

  private startPing(): void {
    this.stopPing();
    this.pingTimer = window.setInterval(() => {
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.ws.send('ping');
      }
    }, 15000);
  }

  private stopPing(): void {
    if (this.pingTimer !== null) {
      clearInterval(this.pingTimer);
      this.pingTimer = null;
    }
  }

  private scheduleReconnect(): void {
    if (!this.shouldReconnect) return;
    this.stopPing();
    const delay = Math.min(1000 * Math.pow(1.5, this.reconnectAttempts), 10000);
    this.reconnectAttempts++;
    this.reconnectTimer = window.setTimeout(() => {
      this.connect();
    }, delay);
  }

  public disconnect(): void {
    this.shouldReconnect = false;
    this.cleanup();
    this.callbacks.onStatusChange(false);
  }

  private cleanup(): void {
    this.stopPing();
    if (this.reconnectTimer !== null) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.ws) {
      this.ws.onopen = null;
      this.ws.onmessage = null;
      this.ws.onclose = null;
      this.ws.onerror = null;
      this.ws.close();
      this.ws = null;
    }
  }
}
