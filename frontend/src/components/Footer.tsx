import { Github, Twitter, Linkedin } from 'lucide-react';

const Footer = () => {
  const links = {
    produit: [
      { name: 'Fonctionnalités', href: '#features' },
      { name: 'Tarifs', href: '#pricing' },
      { name: 'Documentation', href: '#docs' },
      { name: 'Changelog', href: '#changelog' },
    ],
    ressources: [
      { name: 'Blog', href: '#blog' },
      { name: 'Guides', href: '#guides' },
      { name: 'API', href: '#api' },
      { name: 'Status', href: '#status' },
    ],
    entreprise: [
      { name: 'À propos', href: '#about' },
      { name: 'Carrières', href: '#careers' },
      { name: 'Contact', href: '#contact' },
    ],
  };

  const socials = [
    { icon: Github, href: '#', label: 'GitHub' },
    { icon: Twitter, href: '#', label: 'Twitter' },
    { icon: Linkedin, href: '#', label: 'LinkedIn' },
  ];

  return (
    <footer className="relative border-t border-border/50">
      <div className="absolute inset-0 bg-card/30" />
      
      <div className="container mx-auto px-6 relative z-10">
        {/* Main Footer */}
        <div className="py-16 grid grid-cols-2 md:grid-cols-5 gap-8">
          {/* Brand Column */}
          <div className="col-span-2">
            <a href="#" className="flex items-center gap-3 mb-6">
              <div className="relative w-10 h-10 flex items-center justify-center">
                <div className="absolute inset-0 bg-gradient-to-br from-primary to-accent rounded-xl opacity-20" />
                <svg viewBox="0 0 24 24" className="w-6 h-6 text-primary relative z-10">
                  <path
                    fill="currentColor"
                    d="M12 2L2 7v10l10 5 10-5V7L12 2zm0 2.5l6.5 3.25L12 11 5.5 7.75 12 4.5zM4 8.75l7 3.5v7l-7-3.5v-7zm9 10.5v-7l7-3.5v7l-7 3.5z"
                  />
                </svg>
              </div>
              <span className="text-xl font-semibold">Adversum</span>
            </a>
            <p className="text-sm text-muted-foreground mb-6 max-w-xs leading-relaxed">
              Sécurité applicative de nouvelle génération propulsée par Rust et l'intelligence artificielle.
            </p>
            {/* Social Links */}
            <div className="flex items-center gap-2">
              {socials.map((social, i) => (
                <a
                  key={i}
                  href={social.href}
                  aria-label={social.label}
                  className="p-2.5 rounded-full bg-card/50 hover:bg-primary/10 hover:text-primary transition-all duration-300"
                >
                  <social.icon className="w-4 h-4" />
                </a>
              ))}
            </div>
          </div>

          {/* Links Columns */}
          <div>
            <h4 className="text-sm font-semibold mb-4 uppercase tracking-wide">Produit</h4>
            <ul className="space-y-3">
              {links.produit.map((link, i) => (
                <li key={i}>
                  <a
                    href={link.href}
                    className="text-sm text-muted-foreground hover:text-foreground transition-colors"
                  >
                    {link.name}
                  </a>
                </li>
              ))}
            </ul>
          </div>

          <div>
            <h4 className="text-sm font-semibold mb-4 uppercase tracking-wide">Ressources</h4>
            <ul className="space-y-3">
              {links.ressources.map((link, i) => (
                <li key={i}>
                  <a
                    href={link.href}
                    className="text-sm text-muted-foreground hover:text-foreground transition-colors"
                  >
                    {link.name}
                  </a>
                </li>
              ))}
            </ul>
          </div>

          <div>
            <h4 className="text-sm font-semibold mb-4 uppercase tracking-wide">Entreprise</h4>
            <ul className="space-y-3">
              {links.entreprise.map((link, i) => (
                <li key={i}>
                  <a
                    href={link.href}
                    className="text-sm text-muted-foreground hover:text-foreground transition-colors"
                  >
                    {link.name}
                  </a>
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* Bottom Bar */}
        <div className="py-6 border-t border-border/50 flex flex-col md:flex-row items-center justify-between gap-4">
          <p className="text-sm text-muted-foreground">
            © 2024 Adversum. Tous droits réservés.
          </p>
          <div className="flex items-center gap-6 text-sm text-muted-foreground">
            <a href="#" className="hover:text-foreground transition-colors">Confidentialité</a>
            <a href="#" className="hover:text-foreground transition-colors">CGU</a>
            <a href="#" className="hover:text-foreground transition-colors">Cookies</a>
          </div>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
