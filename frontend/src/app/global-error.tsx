'use client';

import React from 'react';

export default function GlobalError({
    error,
    reset,
}: {
    error: Error & { digest?: string };
    reset: () => void;
}) {
    return (
        <html>
            <body className="bg-black text-white min-h-screen flex items-center justify-center p-4 font-mono">
                <div className="max-w-md w-full bg-slate-900 border border-red-900/50 p-8 rounded-lg shadow-2xl shadow-red-900/20 backdrop-blur-xl">
                    <h2 className="text-2xl font-bold text-red-500 mb-4">CRITICAL SYSTEM FAILURE</h2>
                    <p className="text-gray-400 mb-6 border-l-2 border-red-500/30 pl-4 py-1">
                        {error.message || "An unrecoverable error occurred in the neural interface."}
                    </p>
                    <div className="flex gap-4">
                        <button
                            className="bg-red-600/20 hover:bg-red-600/30 text-red-400 border border-red-600/50 px-6 py-2 rounded transition-all duration-300 w-full hover:scale-[1.02] active:scale-[0.98]"
                            onClick={() => reset()}
                        >
                            REBOOT SYSTEM
                        </button>
                        <button
                            className="bg-slate-800 hover:bg-slate-700 text-gray-400 border border-slate-700 px-6 py-2 rounded transition-all duration-300 w-full"
                            onClick={() => window.location.reload()}
                        >
                            HARD RELOAD
                        </button>
                    </div>
                    <div className="mt-8 text-xs text-slate-600 font-mono text-center">
                        ERROR_DIGEST: {error.digest || 'UNKNOWN'}
                    </div>
                </div>
            </body>
        </html>
    );
}
