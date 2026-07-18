import { useRef, useEffect, useState } from 'react';

const steps = [
  {
    number: '01',
    title: 'Intégration',
    description: 'Connectez votre repository en quelques secondes. GitHub, GitLab, Bitbucket supportés.',
  },
  {
    number: '02',
    title: 'Analyse',
    description: 'Notre moteur Rust analyse votre code avec une précision chirurgicale.',
  },
  {
    number: '03',
    title: 'Validation IA',
    description: 'L\'intelligence artificielle confirme les vulnérabilités et élimine les faux positifs.',
  },
  {
    number: '04',
    title: 'Correction',
    description: 'Des patches sont générés et vérifiés automatiquement.',
  },
  {
    number: '05',
    title: 'Déploiement',
    description: 'Déployez en un clic avec rollback automatique si nécessaire.',
  },
];

const HowItWorksSection = () => {
  const sectionRef = useRef<HTMLDivElement>(null);
  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setIsVisible(true);
        }
      },
      { threshold: 0.1 }
    );

    if (sectionRef.current) {
      observer.observe(sectionRef.current);
    }

    return () => observer.disconnect();
  }, []);

  return (
    <section id="how-it-works" ref={sectionRef} className="relative py-32 overflow-hidden">
      {/* Background gradient */}
      <div className="absolute inset-0 bg-gradient-to-b from-background via-card/30 to-background" />
      
      <div className="container mx-auto px-6 relative z-10">
        {/* Section Header */}
        <div className="text-center max-w-3xl mx-auto mb-20">
          <span className="text-xs uppercase tracking-[0.3em] text-muted-foreground mb-4 block">
            Processus
          </span>
          <h2 className="text-4xl md:text-5xl lg:text-6xl font-bold mb-6 tracking-tight">
            Simple et{' '}
            <span className="bg-gradient-to-r from-primary to-accent bg-clip-text text-transparent">
              efficace
            </span>
          </h2>
          <p className="text-lg text-muted-foreground leading-relaxed">
            De l'intégration au déploiement, tout est automatisé
          </p>
        </div>

        {/* Steps */}
        <div className="max-w-4xl mx-auto">
          {steps.map((step, index) => (
            <div
              key={index}
              className={`relative flex items-start gap-8 mb-16 last:mb-0 transition-all duration-700 ${
                isVisible 
                  ? 'opacity-100 translate-x-0' 
                  : 'opacity-0 -translate-x-8'
              }`}
              style={{ transitionDelay: `${index * 150}ms` }}
            >
              {/* Number */}
              <div className="flex-shrink-0 w-20 h-20 flex items-center justify-center">
                <span className="text-5xl font-bold text-muted-foreground/20">
                  {step.number}
                </span>
              </div>

              {/* Content */}
              <div className="flex-1 pt-2">
                <h3 className="text-2xl md:text-3xl font-semibold mb-3">
                  {step.title}
                </h3>
                <p className="text-muted-foreground text-lg leading-relaxed max-w-lg">
                  {step.description}
                </p>
              </div>

              {/* Connection line */}
              {index < steps.length - 1 && (
                <div className="absolute left-10 top-24 w-px h-16 bg-gradient-to-b from-border to-transparent" />
              )}
            </div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default HowItWorksSection;
