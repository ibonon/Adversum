import { useState, useRef, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Check, X, Zap, Shield, Crown } from 'lucide-react';

const plans = [
  {
    name: 'Starter',
    icon: Zap,
    price: { monthly: 49, annual: 39 },
    description: 'Pour les équipes qui démarrent avec la sécurité applicative.',
    features: [
      '5 projets',
      '1 000 scans / mois',
      'Détection OWASP Top 10',
      'Rapports PDF',
      'Support email',
    ],
    cta: 'Commencer',
    popular: false,
    gradient: 'from-muted to-muted/50',
  },
  {
    name: 'Pro',
    icon: Shield,
    price: { monthly: 149, annual: 119 },
    description: 'Pour les équipes de développement sérieuses sur la sécurité.',
    features: [
      '25 projets',
      '10 000 scans / mois',
      'Analyse hybride Rust + IA',
      'Correction automatique AVR',
      'Dashboard temps réel',
      'Intégrations CI/CD',
      'Support prioritaire',
    ],
    cta: 'Essai gratuit 14 jours',
    popular: true,
    gradient: 'from-primary to-accent',
  },
  {
    name: 'Enterprise',
    icon: Crown,
    price: { monthly: null, annual: null },
    description: 'Pour les organisations avec des besoins de sécurité avancés.',
    features: [
      'Projets illimités',
      'Scans illimités',
      'Système immunitaire RBAT',
      'Graphes d\'attaque avancés',
      'SSO & SAML',
      'API dédiée',
      'SLA garanti 99.99%',
      'Account manager dédié',
    ],
    cta: 'Contacter l\'équipe',
    popular: false,
    gradient: 'from-warning to-warning/50',
  },
];

const comparisonFeatures = [
  { category: 'Analyse', features: [
    { name: 'Analyse statique (AST)', starter: true, pro: true, enterprise: true },
    { name: 'Flux de données & CFG', starter: false, pro: true, enterprise: true },
    { name: 'Validation IA (LLM)', starter: false, pro: true, enterprise: true },
    { name: 'Analyse inter-fichiers', starter: false, pro: false, enterprise: true },
  ]},
  { category: 'Correction', features: [
    { name: 'Suggestions de correctifs', starter: true, pro: true, enterprise: true },
    { name: 'Correction automatique AVR', starter: false, pro: true, enterprise: true },
    { name: 'Vérification des patches', starter: false, pro: true, enterprise: true },
    { name: 'Rollback automatique', starter: false, pro: false, enterprise: true },
  ]},
  { category: 'Dashboard', features: [
    { name: 'Rapports de base', starter: true, pro: true, enterprise: true },
    { name: 'Graphes d\'attaque', starter: false, pro: true, enterprise: true },
    { name: 'Historique complet', starter: false, pro: true, enterprise: true },
    { name: 'Tableaux de bord personnalisés', starter: false, pro: false, enterprise: true },
  ]},
  { category: 'Sécurité avancée', features: [
    { name: 'OWASP Top 10', starter: true, pro: true, enterprise: true },
    { name: 'CWE / SANS Top 25', starter: false, pro: true, enterprise: true },
    { name: 'Système immunitaire RBAT', starter: false, pro: false, enterprise: true },
    { name: 'Pentest autonome simulé', starter: false, pro: false, enterprise: true },
  ]},
  { category: 'Support & Intégrations', features: [
    { name: 'Support email', starter: true, pro: true, enterprise: true },
    { name: 'Support prioritaire', starter: false, pro: true, enterprise: true },
    { name: 'CI/CD (GitHub, GitLab…)', starter: false, pro: true, enterprise: true },
    { name: 'SSO / SAML / SCIM', starter: false, pro: false, enterprise: true },
    { name: 'SLA garanti', starter: false, pro: false, enterprise: true },
    { name: 'Account manager dédié', starter: false, pro: false, enterprise: true },
  ]},
];

const PricingSection = () => {
  const [isAnnual, setIsAnnual] = useState(true);
  const sectionRef = useRef<HTMLDivElement>(null);
  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => { if (entry.isIntersecting) setIsVisible(true); },
      { threshold: 0.1 }
    );
    if (sectionRef.current) observer.observe(sectionRef.current);
    return () => observer.disconnect();
  }, []);

  return (
    <section id="pricing" ref={sectionRef} className="relative py-32 overflow-hidden">
      <div className="absolute inset-0 bg-gradient-to-b from-background via-card/30 to-background pointer-events-none" />

      <div className="container mx-auto px-6 relative z-10">
        {/* Header */}
        <div className="text-center max-w-3xl mx-auto mb-6">
          <span className="text-xs uppercase tracking-[0.3em] text-muted-foreground mb-4 block">
            Tarifs
          </span>
          <h2 className="text-4xl md:text-5xl lg:text-6xl font-bold mb-6 tracking-tight">
            Un plan pour chaque{' '}
            <span className="bg-gradient-to-r from-primary to-accent bg-clip-text text-transparent">
              ambition
            </span>
          </h2>
          <p className="text-lg text-muted-foreground leading-relaxed">
            Commencez gratuitement, évoluez sans limites.
          </p>
        </div>

        {/* Toggle */}
        <div className="flex items-center justify-center gap-4 mb-16">
          <span className={`text-sm transition-colors ${!isAnnual ? 'text-foreground' : 'text-muted-foreground'}`}>
            Mensuel
          </span>
          <button
            onClick={() => setIsAnnual(!isAnnual)}
            className={`relative w-14 h-7 rounded-full transition-colors duration-300 ${
              isAnnual ? 'bg-primary' : 'bg-muted'
            }`}
          >
            <div className={`absolute top-1 w-5 h-5 rounded-full bg-background shadow-md transition-transform duration-300 ${
              isAnnual ? 'translate-x-8' : 'translate-x-1'
            }`} />
          </button>
          <span className={`text-sm transition-colors ${isAnnual ? 'text-foreground' : 'text-muted-foreground'}`}>
            Annuel
          </span>
          {isAnnual && (
            <span className="text-xs font-medium text-primary bg-primary/10 px-3 py-1 rounded-full">
              -20%
            </span>
          )}
        </div>

        {/* Cards */}
        <div className="grid md:grid-cols-3 gap-6 max-w-6xl mx-auto mb-32">
          {plans.map((plan, index) => (
            <div
              key={plan.name}
              className={`relative transition-all duration-700 ${
                isVisible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-12'
              }`}
              style={{ transitionDelay: `${index * 150}ms` }}
            >
              {plan.popular && (
                <div className="absolute -top-4 left-1/2 -translate-x-1/2 z-20">
                  <span className="bg-gradient-to-r from-primary to-accent text-primary-foreground text-xs font-semibold px-4 py-1.5 rounded-full shadow-lg shadow-primary/20">
                    Le plus populaire
                  </span>
                </div>
              )}
              <div className={`relative h-full flex flex-col p-8 md:p-10 rounded-3xl border transition-all duration-500 overflow-hidden ${
                plan.popular
                  ? 'bg-card border-primary/30 shadow-2xl shadow-primary/10 scale-[1.02]'
                  : 'bg-card/50 border-border/50 hover:border-border'
              }`}>
                {/* Subtle gradient bg for popular */}
                {plan.popular && (
                  <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-accent/5 pointer-events-none" />
                )}

                <div className="relative z-10 flex flex-col h-full">
                  {/* Icon & Name */}
                  <div className="flex items-center gap-3 mb-4">
                    <div className={`p-2.5 rounded-xl bg-gradient-to-br ${plan.gradient}`}>
                      <plan.icon className="w-5 h-5 text-background" />
                    </div>
                    <h3 className="text-xl font-semibold">{plan.name}</h3>
                  </div>

                  {/* Price */}
                  <div className="mb-4">
                    {plan.price.monthly ? (
                      <div className="flex items-baseline gap-1">
                        <span className="text-5xl font-bold tracking-tight">
                          {isAnnual ? plan.price.annual : plan.price.monthly}€
                        </span>
                        <span className="text-muted-foreground text-sm">/mois</span>
                      </div>
                    ) : (
                      <div className="text-3xl font-bold tracking-tight">Sur mesure</div>
                    )}
                  </div>

                  <p className="text-sm text-muted-foreground mb-8 leading-relaxed">
                    {plan.description}
                  </p>

                  {/* Features */}
                  <ul className="space-y-3 mb-10 flex-1">
                    {plan.features.map((feature) => (
                      <li key={feature} className="flex items-start gap-3">
                        <Check className="w-4 h-4 text-primary mt-0.5 shrink-0" />
                        <span className="text-sm text-foreground/80">{feature}</span>
                      </li>
                    ))}
                  </ul>

                  {/* CTA */}
                  <Button
                    variant={plan.popular ? 'hero' : 'outline'}
                    size="lg"
                    className="w-full rounded-xl"
                  >
                    {plan.cta}
                  </Button>
                </div>
              </div>
            </div>
          ))}
        </div>

        {/* Comparison Table */}
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-12">
            <h3 className="text-3xl md:text-4xl font-bold mb-4 tracking-tight">
              Comparatif détaillé
            </h3>
            <p className="text-muted-foreground">
              Toutes les fonctionnalités en un coup d'œil
            </p>
          </div>

          <div className="rounded-2xl border border-border/50 overflow-hidden bg-card/30 backdrop-blur-sm">
            {/* Table header */}
            <div className="grid grid-cols-4 gap-4 p-6 bg-card/50 border-b border-border/50">
              <div className="text-sm font-medium text-muted-foreground">Fonctionnalité</div>
              <div className="text-center text-sm font-semibold">Starter</div>
              <div className="text-center text-sm font-semibold text-primary">Pro</div>
              <div className="text-center text-sm font-semibold">Enterprise</div>
            </div>

            {comparisonFeatures.map((group) => (
              <div key={group.category}>
                {/* Category header */}
                <div className="px-6 py-4 bg-muted/30 border-b border-border/30">
                  <span className="text-xs uppercase tracking-[0.2em] font-medium text-muted-foreground">
                    {group.category}
                  </span>
                </div>
                {/* Features */}
                {group.features.map((feature, idx) => (
                  <div
                    key={feature.name}
                    className={`grid grid-cols-4 gap-4 px-6 py-4 ${
                      idx < group.features.length - 1 ? 'border-b border-border/20' : ''
                    } hover:bg-muted/10 transition-colors`}
                  >
                    <div className="text-sm text-foreground/80">{feature.name}</div>
                    {(['starter', 'pro', 'enterprise'] as const).map((tier) => (
                      <div key={tier} className="flex justify-center">
                        {feature[tier] ? (
                          <Check className={`w-4 h-4 ${tier === 'pro' ? 'text-primary' : 'text-foreground/50'}`} />
                        ) : (
                          <X className="w-4 h-4 text-muted-foreground/30" />
                        )}
                      </div>
                    ))}
                  </div>
                ))}
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
};

export default PricingSection;
