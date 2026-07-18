"use client";

import { useWebSocket } from "@/lib/useWebSocket";

export default function RealTimeUpdates() {
    // This component purely handles the side effects of the WebSocket connection
    // (toast notifications and query invalidation)
    useWebSocket();
    return null;
}
