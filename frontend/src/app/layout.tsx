import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import Sidebar from "@/components/Sidebar";
import KeyboardShortcutsWrapper from "@/components/KeyboardShortcutsWrapper";
import RealTimeUpdates from "@/components/RealTimeUpdates";
import SkipToContent from "@/components/SkipToContent";
import Providers from "./providers";
import { ErrorBoundary } from "@/components/ErrorBoundary";

const inter = Inter({ subsets: ["latin"], weight: ["400", "500", "600", "700", "800", "900"] });

export const metadata: Metadata = {
  title: "Adversum | High-Tech Deterministic Security",
  description: "Advanced AI-Powered Security Reasoning Engine",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className={`${inter.className} bg-black text-white antialiased`}>
        <Providers>
          <RealTimeUpdates />
          <SkipToContent />
          <KeyboardShortcutsWrapper>
            <div className="flex min-h-screen">
              <Sidebar />
              <main id="main-content" className="flex-1 relative overflow-y-auto outline-none" tabIndex={-1}>
                <div className="aurora-bg">
                  <div className="aurora-spot -top-40 -left-40 bg-accentBlue/10" />
                  <div className="aurora-spot top-1/2 -right-40 bg-accentPurple/10" />
                </div>
                <div className="p-10 max-w-7xl mx-auto">
                  <ErrorBoundary widgetName="Page Content">
                    {children}
                  </ErrorBoundary>
                </div>
              </main>
            </div>
          </KeyboardShortcutsWrapper>
        </Providers>
      </body>
    </html>
  );
}
