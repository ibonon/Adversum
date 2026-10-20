import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import Index from "./pages/Index";
import NotFound from "./pages/NotFound";
import ErrorBoundary from "./components/ErrorBoundary";
import SOCDashboard from "./pages/SOC";
import WarRoom from "./pages/WarRoom";
import Analytics from "./pages/Analytics";


const queryClient = new QueryClient();

const App = () => (
  <ErrorBoundary>
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <Toaster />
        <Sonner />
        <BrowserRouter>
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
        </BrowserRouter>
      </TooltipProvider>
    </QueryClientProvider>
  </ErrorBoundary>
);

export default App;
