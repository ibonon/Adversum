import { Component, type ReactNode } from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

class ErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false, error: null };

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error('ErrorBoundary caught an error:', error, errorInfo);
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null });
  };

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return this.props.fallback;
      }

      return (
        <section className="relative py-20 overflow-hidden">
          <div className="absolute inset-0 bg-gradient-to-b from-background via-card/20 to-background" />
          <div className="container mx-auto px-6 relative z-10">
            <div className="max-w-2xl mx-auto rounded-2xl bg-card/80 backdrop-blur-xl border border-destructive/20 p-8 text-center shadow-2xl shadow-destructive/5">
              <div className="w-14 h-14 rounded-full bg-destructive/10 flex items-center justify-center mx-auto mb-5">
                <AlertTriangle className="w-7 h-7 text-destructive" />
              </div>
              <h2 className="text-2xl md:text-3xl font-bold mb-3 tracking-tight">
                Component Recovery
              </h2>
              <p className="text-muted-foreground mb-5 leading-relaxed text-sm">
                A visual module encountered a runtime rendering exception. The core platform and security scanning services remain fully functional.
              </p>
              {this.state.error && (
                <div className="mb-5 p-3 rounded-lg bg-destructive/5 border border-destructive/10 text-left">
                  <p className="text-xs font-mono text-destructive/80">
                    {this.state.error.message}
                  </p>
                </div>
              )}
              <button
                onClick={this.handleReset}
                className="inline-flex items-center gap-2 px-5 py-2.5 rounded-full bg-primary text-primary-foreground text-sm font-medium hover:bg-primary/90 transition-colors"
              >
                <RefreshCw className="w-4 h-4" />
                Retry Component
              </button>
            </div>
          </div>
        </section>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
