"use client";

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState } from "react";
import { FocusModeProvider } from "@/contexts/FocusModeContext";
import { Toaster } from "react-hot-toast";

export default function Providers({ children }: { children: React.ReactNode }) {
    const [queryClient] = useState(() => new QueryClient({
        defaultOptions: {
            queries: {
                staleTime: 5 * 1000, // 5 seconds stale time for real-time feel
                refetchOnWindowFocus: true,
                retry: 3,
                retryDelay: (attemptIndex) => Math.min(1000 * 2 ** attemptIndex, 30000),
            },
        },
    }));

    return (
        <QueryClientProvider client={queryClient}>
            <FocusModeProvider>
                {children}
                <Toaster
                    position="top-right"
                    toastOptions={{
                        className: "",
                        style: {
                            background: "rgba(15, 23, 42, 0.95)",
                            color: "#fff",
                            border: "1px solid rgba(255, 255, 255, 0.1)",
                            backdropFilter: "blur(10px)",
                        },
                        success: {
                            iconTheme: {
                                primary: "#10b981",
                                secondary: "#000",
                            },
                        },
                        error: {
                            iconTheme: {
                                primary: "#ef4444",
                                secondary: "#000",
                            },
                        },
                    }}
                />
            </FocusModeProvider>
        </QueryClientProvider>
    );
}
