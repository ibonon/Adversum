import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './App.css';

// Mocking some D3 visualization component
const AttackGraph = ({ findings }) => {
    return (
        <div className="p-4 border rounded bg-gray-900 text-white">
            <h3 className="text-xl font-bold mb-4">Attack Graph</h3>
            <div className="flex justify-center items-center h-64 bg-gray-800 rounded">
                {findings.length > 0 ? (
                    <p>Graph nodes: {findings.length * 3}</p> // Mock
                ) : (
                    <p>No findings to display</p>
                )}
            </div>
        </div>
    );
};

function App() {
    const [repoUrl, setRepoUrl] = useState('');
    const [status, setStatus] = useState(null);
    const [report, setReport] = useState(null);

    const submitAudit = async () => {
        try {
            const res = await axios.post('http://localhost:8000/audit', { repo_url: repoUrl });
            setStatus(res.data);
            pollStatus(res.data.id);
        } catch (err) {
            console.error(err);
        }
    };

    const pollStatus = (jobId) => {
        const interval = setInterval(async () => {
            const res = await axios.get(`http://localhost:8000/audit/${jobId}`);
            if (res.data.status === 'completed') {
                setReport(res.data.result);
                clearInterval(interval);
            } else if (res.data.status === 'failed') {
                clearInterval(interval);
            }
            setStatus(res.data);
        }, 2000);
    };

    return (
        <div className="min-h-screen bg-gray-950 text-gray-100 p-8 font-sans">
            <header className="mb-8">
                <h1 className="text-4xl font-bold text-red-500 tracking-tighter">ADVERSUM</h1>
                <p className="text-gray-400">AI Security Reasoning Engine</p>
            </header>

            <main className="max-w-4xl mx-auto space-y-8">
                <section className="bg-gray-900 p-6 rounded-lg shadow-lg border border-gray-800">
                    <h2 className="text-2xl font-semibold mb-4">Start New Audit</h2>
                    <div className="flex gap-4">
                        <input
                            type="text"
                            placeholder="https://github.com/..."
                            className="flex-1 p-3 bg-gray-800 rounded border border-gray-700 text-white"
                            value={repoUrl}
                            onChange={(e) => setRepoUrl(e.target.value)}
                        />
                        <button
                            onClick={submitAudit}
                            className="px-6 py-3 bg-red-600 hover:bg-red-700 rounded font-bold transition-colors"
                        >
                            AUDIT
                        </button>
                    </div>
                    {status && (
                        <div className="mt-4 p-3 bg-gray-800 rounded">
                            <span className="text-yellow-400 font-mono">STATUS: {status.status.toUpperCase()}</span>
                        </div>
                    )}
                </section>

                {report && (
                    <section className="space-y-6">
                        <div className="grid grid-cols-2 gap-6">
                            <div className="bg-gray-900 p-6 rounded border border-gray-800">
                                <h3 className="text-gray-400 uppercase text-xs font-bold">Files Analyzed</h3>
                                <p className="text-3xl font-mono">{report.stats.files_analyzed}</p>
                            </div>
                            <div className="bg-gray-900 p-6 rounded border border-gray-800">
                                <h3 className="text-gray-400 uppercase text-xs font-bold">Critical Issues</h3>
                                <p className="text-3xl font-mono text-red-500">{report.findings.length}</p>
                            </div>
                        </div>

                        <AttackGraph findings={report.findings} />

                        <div className="bg-gray-900 p-6 rounded border border-gray-800">
                            <h3 className="text-xl font-bold mb-4">Findings</h3>
                            {report.findings.map((finding, i) => (
                                <div key={i} className="mb-4 p-4 bg-gray-950 rounded border-l-4 border-red-500">
                                    <div className="flex justify-between items-center mb-2">
                                        <h4 className="font-bold text-lg">{finding.vuln}</h4>
                                        <span className="text-xs px-2 py-1 bg-red-900 text-red-100 rounded">{finding.severity}</span>
                                    </div>
                                    <p className="text-sm text-gray-400 font-mono mb-2">{finding.file}</p>
                                    <p className="text-sm">High confidence ({finding.confidence * 100}%) detection.</p>
                                </div>
                            ))}
                        </div>
                    </section>
                )}
            </main>
        </div>
    );
}

export default App;
