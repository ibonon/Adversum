import { lazy, Suspense } from "react";
import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import NotFound from "./pages/NotFound";
import ErrorBoundary from "./components/ErrorBoundary";

// ── Code splitting ────────────────────────────────────────────────────────────
// Les 4 pages sont chargées à la demande : three.js (@react-three/*), recharts et
// @xyflow/react ne sont plus tirés dans le chunk initial. La page d'accueil
// elle-même est un chunk séparé, ce qui garde le shell de l'app minimal.
const Index = lazy(() => import("./pages/Index"));
const SOCDashboard = lazy(() => import("./pages/SOC"));
const WarRoom = lazy(() => import("./pages/WarRoom"));
const Analytics = lazy(() => import("./pages/Analytics"));

const PageFallback = () => (
  <div className="min-h-screen bg-background text-foreground flex items-center justify-center">
    <div className="flex flex-col items-center gap-3">
      <div className="h-8 w-8 animate-spin rounded-full border-2 border-cyan-500 border-t-transparent" />
      <span className="text-xs uppercase tracking-widest text-slate-400">Loading…</span>
    </div>
  </div>
);

const queryClient = new QueryClient();

const App = () => (
  <ErrorBoundary>
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <Toaster />
        <Sonner />
        <BrowserRouter>
          <Suspense fallback={<PageFallback />}>
            <Routes>
              <Route path="/" element={<Index />} />
              {/* Phase 2: AI-ASOC Real-Time SOC Dashboard */}
              <Route path="/soc" element={<SOCDashboard />} />
              {/* Phase 3: Cross-Protocol Attack Simulator War Room */}
              <Route path="/war-room" element={<WarRoom />} />
              {/* Analytics & Observability Dashboard */}
              <Route path="/analytics" element={<Analytics />} />

              {/* ADD ALL CUSTOM ROUTES ABOVE THE CATCH-ALL "*" ROUTE */}
              <Route path="*" element={<NotFound />} />
            </Routes>
          </Suspense>
        </BrowserRouter>
      </TooltipProvider>
    </QueryClientProvider>
  </ErrorBoundary>
);

export default App;
