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
        <section className="relative py-32 overflow-hidden">
          <div className="absolute inset-0 bg-gradient-to-b from-background via-card/20 to-background" />
          <div className="container mx-auto px-6 relative z-10">
            <div className="max-w-2xl mx-auto rounded-2xl bg-card/80 backdrop-blur-xl border border-destructive/20 p-10 text-center shadow-2xl shadow-destructive/5">
              <div className="w-16 h-16 rounded-full bg-destructive/10 flex items-center justify-center mx-auto mb-6">
                <AlertTriangle className="w-8 h-8 text-destructive" />
              </div>
              <h2 className="text-3xl md:text-4xl font-bold mb-4 tracking-tight">
                Simulation en maintenance
              </h2>
              <p className="text-muted-foreground mb-6 leading-relaxed">
                La démonstration en temps réel a rencontré un problème. Le reste du site fonctionne normalement.
              </p>
              {this.state.error && (
                <div className="mb-6 p-4 rounded-lg bg-destructive/5 border border-destructive/10 text-left">
                  <p className="text-xs font-mono text-destructive/80">
                    {this.state.error.message}
                  </p>
                </div>
              )}
              <button
                onClick={this.handleReset}
                className="inline-flex items-center gap-2 px-6 py-3 rounded-full bg-primary text-primary-foreground font-medium hover:bg-primary/90 transition-colors"
              >
                <RefreshCw className="w-4 h-4" />
                Réessayer la simulation
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
