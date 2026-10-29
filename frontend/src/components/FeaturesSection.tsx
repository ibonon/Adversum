import { useRef, useEffect, useState } from 'react';
import { Cpu, Bot, LayoutDashboard, ShieldAlert } from 'lucide-react';
import Scene3D from './Scene3D';

const features = [
  {
    icon: Cpu,
    title: 'Hybrid Analysis Engine',
    description: 'Ultra-fast Rust PyO3 core combined with NVIDIA Nemotron LLM for surgical vulnerability detection.',
    color: 'from-primary to-primary/50',
  },
  {
    icon: Bot,
    title: 'Autonomous Patching',
    description: 'Automatic synthesis and BitVec formal verification of secured patches with zero human latency.',
    color: 'from-accent to-accent/50',
  },
  {
    icon: LayoutDashboard,
    title: 'Real-Time Telemetry',
    description: 'Institutional glassmorphism UI to monitor, trace, and inspect multi-tier security audits live.',
    color: 'from-success to-success/50',
  },
  {
    icon: ShieldAlert,
    title: 'Autonomous Cyber Defense',
    description: 'Cross-Protocol War Room simulating real adversarial payloads to preempt zero-day exploits.',
    color: 'from-warning to-warning/50',
  },
];

const FeaturesSection = () => {
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

  return (
    <section id="features" ref={sectionRef} className="relative py-32 overflow-hidden">
      {/* 3D Background */}
      <Scene3D variant="features" />
      
      {/* Gradient overlay */}
      <div className="absolute inset-0 bg-gradient-to-b from-background via-background/95 to-background pointer-events-none" />
      
      <div className="container mx-auto px-6 relative z-10">
        {/* Section Header */}
        <div className="text-center max-w-3xl mx-auto mb-20">
          <span className="text-xs uppercase tracking-[0.3em] text-muted-foreground mb-4 block">
            Capabilities
          </span>
          <h2 className="text-4xl md:text-5xl lg:text-6xl font-bold mb-6 tracking-tight">
            Comprehensive{' '}
            <span className="bg-gradient-to-r from-primary to-accent bg-clip-text text-transparent">
              Protection
            </span>
          </h2>
          <p className="text-lg text-muted-foreground leading-relaxed">
            Four core pillars redefining modern smart contract and cloud security
          </p>
        </div>

        {/* Features Grid */}
        <div className="grid md:grid-cols-2 gap-6 max-w-5xl mx-auto">
          {features.map((feature, index) => (
            <div
              key={index}
              className={`group relative transition-all duration-700 ${
                isVisible 
                  ? 'opacity-100 translate-y-0' 
                  : 'opacity-0 translate-y-8'
              }`}
              style={{ transitionDelay: `${index * 100}ms` }}
            >
              <div className="relative h-full p-8 md:p-10 rounded-3xl bg-card/50 backdrop-blur-sm border border-border/50 hover:border-border transition-all duration-500 overflow-hidden">
                {/* Hover gradient */}
                <div className={`absolute inset-0 bg-gradient-to-br ${feature.color} opacity-0 group-hover:opacity-5 transition-opacity duration-500`} />
                
                {/* Icon */}
                <div className={`inline-flex p-4 rounded-2xl bg-gradient-to-br ${feature.color} mb-6`}>
                  <feature.icon className="w-6 h-6 text-background" />
                </div>

                {/* Content */}
                <h3 className="text-xl md:text-2xl font-semibold mb-4 group-hover:text-primary transition-colors duration-300">
                  {feature.title}
                </h3>
                <p className="text-muted-foreground leading-relaxed">
                  {feature.description}
                </p>

                {/* Subtle corner decoration */}
                <div className="absolute bottom-0 right-0 w-32 h-32 bg-gradient-to-tl from-primary/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500 rounded-tl-full" />
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default FeaturesSection;
