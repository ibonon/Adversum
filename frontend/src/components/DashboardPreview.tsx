import { useRef, useEffect, useState } from 'react';
import { AlertTriangle, CheckCircle, Clock, TrendingUp, Download, FileCode, Wrench } from 'lucide-react';

const DashboardPreview = () => {
  const sectionRef = useRef<HTMLDivElement>(null);
  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setIsVisible(true);
        }
      },
      { threshold: 0.2 }
    );

    if (sectionRef.current) {
      observer.observe(sectionRef.current);
    }

    return () => observer.disconnect();
  }, []);

  const vulnerabilities = [
    { severity: 'critical', name: 'Reentrancy', file: 'contracts/Vault.sol', module: 'Solidity', status: 'analyzing' },
    { severity: 'high', name: 'Hardcoded JWT Key', file: 'api/auth.py', module: 'Crypto', status: 'pending' },
    { severity: 'high', name: 'Root User in Docker', file: 'infra/Dockerfile', module: 'IaC', status: 'fixed' },
    { severity: 'medium', name: 'Tainted Data Flow', file: 'core/parser.js', module: 'Taint Core', status: 'analyzing' },
  ];

  return (
    <section ref={sectionRef} className="relative py-32 overflow-hidden">
      {/* Background */}
      <div className="absolute inset-0 bg-gradient-to-b from-background to-card/20" />
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[600px] bg-primary/5 rounded-full blur-3xl" />
      
      <div className="container mx-auto px-6 relative z-10">
        {/* Section Header */}
        <div className="text-center max-w-3xl mx-auto mb-16">
          <span className="text-xs uppercase tracking-[0.3em] text-muted-foreground mb-4 block">
            Interface
          </span>
          <h2 className="text-4xl md:text-5xl lg:text-6xl font-bold mb-6 tracking-tight">
            Design{' '}
            <span className="bg-gradient-to-r from-primary to-accent bg-clip-text text-transparent">
              intuitif
            </span>
          </h2>
          <p className="text-lg text-muted-foreground leading-relaxed">
            Une interface épurée pour une productivité maximale
          </p>
        </div>

        {/* Dashboard Mockup */}
        <div 
          className={`relative max-w-5xl mx-auto transition-all duration-1000 ${
            isVisible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-12'
          }`}
        >
          {/* Browser Frame */}
          <div className="rounded-3xl bg-card/80 backdrop-blur-xl border border-border/50 overflow-hidden shadow-2xl shadow-background/50">
            {/* Browser Header */}
            <div className="flex items-center gap-3 px-6 py-4 border-b border-border/50">
              <div className="flex gap-2">
                <div className="w-3 h-3 rounded-full bg-destructive/60" />
                <div className="w-3 h-3 rounded-full bg-warning/60" />
                <div className="w-3 h-3 rounded-full bg-success/60" />
              </div>
              <div className="flex-1 flex justify-center">
                <div className="px-4 py-1.5 rounded-full bg-background/50 text-xs text-muted-foreground font-mono">
                  app.adversum.io/dashboard
                </div>
              </div>
            </div>

            {/* Dashboard Content */}
            <div className="p-8 bg-background/30">
              {/* Git Repo Scan Bar */}
              <div className="mb-8 p-4 rounded-2xl bg-card/60 border border-border/40 backdrop-blur-md">
                <form 
                  onSubmit={(e) => {
                    e.preventDefault();
                    const input = (e.currentTarget.elements.namedItem('repoUrl') as HTMLInputElement)?.value;
                    if (input) {
                      alert(`Scan en cours de : ${input}\n\nL'API clone le dépôt et exécute les modules Adversum (Solidity, Crypto, IaC, Taint).`);
                    }
                  }} 
                  className="flex items-center gap-3"
                >
                  <div className="relative flex-1">
                    <input 
                      type="url"
                      name="repoUrl"
                      placeholder="https://github.com/votre-user/votre-repo..."
                      className="w-full px-4 py-2.5 rounded-xl bg-background/80 border border-border/50 text-sm focus:outline-none focus:ring-2 focus:ring-primary/50 font-mono text-foreground placeholder:text-muted-foreground/60"
                      required
                    />
                  </div>
                  <button 
                    type="submit"
                    className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-primary to-accent text-primary-foreground text-sm font-semibold hover:opacity-90 transition-all flex items-center gap-2 shadow-lg shadow-primary/25 shrink-0"
                  >
                    🚀 Analyser ce Dépôt
                  </button>
                </form>
              </div>

              {/* Stats Row */}
              <div className="grid grid-cols-4 gap-4 mb-8">
                {[
                  { label: 'Vulnérabilités', value: '12', icon: AlertTriangle, color: 'text-destructive' },
                  { label: 'Corrigées', value: '8', icon: CheckCircle, color: 'text-success' },
                  { label: 'En cours', value: '3', icon: Clock, color: 'text-warning' },
                  { label: 'Score', value: '87%', icon: TrendingUp, color: 'text-primary' },
                ].map((stat, i) => (
                  <div 
                    key={i} 
                    className={`p-5 rounded-2xl bg-card/50 border border-border/30 transition-all duration-500 ${
                      isVisible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-4'
                    }`}
                    style={{ transitionDelay: `${300 + i * 100}ms` }}
                  >
                    <stat.icon className={`w-5 h-5 ${stat.color} mb-3`} />
                    <div className="text-2xl font-bold mb-1">{stat.value}</div>
                    <div className="text-sm text-muted-foreground">{stat.label}</div>
                  </div>
                ))}
              </div>

              {/* Vulnerabilities List */}
              <div className="rounded-2xl bg-card/30 border border-border/30 p-6">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-sm font-medium text-muted-foreground uppercase tracking-wide">
                    Vulnérabilités récentes (Multi-Modules)
                  </h3>
                  <div className="flex gap-2">
                    <button className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-background/50 border border-border/50 rounded-lg hover:bg-muted transition-colors">
                      <FileCode className="w-3.5 h-3.5" /> Export SARIF 2.1
                    </button>
                    <button className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-background/50 border border-border/50 rounded-lg hover:bg-muted transition-colors">
                      <Download className="w-3.5 h-3.5" /> Export Markdown
                    </button>
                  </div>
                </div>
                <div className="space-y-3">
                  {vulnerabilities.map((vuln, i) => (
                    <div
                      key={i}
                      className={`flex items-center justify-between p-4 rounded-xl bg-background/50 border border-border/20 transition-all duration-500 ${
                        isVisible ? 'opacity-100 translate-x-0' : 'opacity-0 -translate-x-4'
                      }`}
                      style={{ transitionDelay: `${600 + i * 100}ms` }}
                    >
                      <div className="flex items-center gap-4">
                        <div
                          className={`w-2 h-2 rounded-full ${
                            vuln.severity === 'critical'
                              ? 'bg-destructive'
                              : vuln.severity === 'high'
                              ? 'bg-warning'
                              : 'bg-primary'
                          }`}
                        />
                        <div>
                          <div className="flex items-center gap-2">
                            <div className="text-sm font-medium">{vuln.name}</div>
                            <span className="text-[10px] uppercase tracking-wider px-2 py-0.5 rounded-md bg-muted/50 border border-border/50 text-muted-foreground">
                              {vuln.module}
                            </span>
                          </div>
                          <div className="text-xs text-muted-foreground font-mono">{vuln.file}</div>
                        </div>
                      </div>
                      <div className="flex items-center gap-4">
                        <span
                          className={`px-3 py-1 rounded-full text-xs font-medium ${
                            vuln.status === 'fixed'
                              ? 'bg-success/10 text-success'
                              : vuln.status === 'pending'
                              ? 'bg-warning/10 text-warning'
                              : 'bg-primary/10 text-primary'
                          }`}
                        >
                          {vuln.status === 'fixed' ? 'Corrigé' : vuln.status === 'pending' ? 'En attente' : 'Analyse...'}
                        </span>
                        
                        <button className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 transition-colors shadow-sm">
                          <Wrench className="w-3.5 h-3.5" /> Auto-Fix / Apply Patch
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* Decorative glows */}
          <div className="absolute -top-10 -right-10 w-40 h-40 bg-primary/10 rounded-full blur-3xl" />
          <div className="absolute -bottom-10 -left-10 w-40 h-40 bg-accent/10 rounded-full blur-3xl" />
        </div>
      </div>
    </section>
  );
};

export default DashboardPreview;
