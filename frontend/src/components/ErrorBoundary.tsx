"use client";

import React, { Component, ReactNode } from "react";
import { AlertTriangle, RefreshCw } from "lucide-react";

interface Props {
    children: ReactNode;
    fallback?: ReactNode;
    onError?: (error: Error, errorInfo: React.ErrorInfo) => void;
    widgetName?: string;
}

interface State {
    hasError: boolean;
    error: Error | null;
    errorInfo: React.ErrorInfo | null;
}

export class ErrorBoundary extends Component<Props, State> {
    constructor(props: Props) {
        super(props);
        this.state = {
            hasError: false,
            error: null,
            errorInfo: null,
        };
    }

    static getDerivedStateFromError(error: Error): State {
        return {
            hasError: true,
            error,
            errorInfo: null,
        };
    }

    componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
        console.error("ErrorBoundary caught an error:", error, errorInfo);
        this.setState({
            error,
            errorInfo,
        });
        this.props.onError?.(error, errorInfo);
    }

    handleReset = () => {
        this.setState({
            hasError: false,
            error: null,
            errorInfo: null,
        });
    };

    render() {
        if (this.state.hasError) {
            if (this.props.fallback) {
                return this.props.fallback;
            }

            return (
                <div className="bg-surface/30 border border-red-500/20 rounded-2xl p-8 backdrop-blur-sm">
                    <div className="flex items-start gap-4">
                        <div className="p-3 bg-red-500/10 rounded-lg text-red-500">
                            <AlertTriangle className="w-6 h-6" />
                        </div>
                        <div className="flex-1">
                            <h3 className="text-xl font-bold text-white mb-2">
                                {this.props.widgetName || "Component"} Error
                            </h3>
                            <p className="text-sm text-primaryMuted mb-4">
                                {this.state.error?.message || "An unexpected error occurred"}
                            </p>
                            {process.env.NODE_ENV === "development" && this.state.errorInfo && (
                                <details className="mb-4">
                                    <summary className="text-xs text-white/40 cursor-pointer hover:text-white/60 transition-colors">
                                        Technical Details
                                    </summary>
                                    <pre className="mt-2 p-4 bg-black/50 rounded-lg text-[10px] text-white/60 overflow-auto max-h-40 font-mono">
                                        {this.state.errorInfo.componentStack}
                                    </pre>
                                </details>
                            )}
                            <button
                                onClick={this.handleReset}
                                className="flex items-center gap-2 bg-white text-black px-4 py-2 rounded-lg font-bold text-xs uppercase tracking-wider hover:bg-white/90 transition-colors"
                            >
                                <RefreshCw className="w-4 h-4" />
                                Retry
                            </button>
                        </div>
                    </div>
                </div>
            );
        }

        return this.props.children;
    }
}
