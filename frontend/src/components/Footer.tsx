import { Github, Twitter, Linkedin, Shield } from 'lucide-react';

const Footer = () => {
  const links = {
    product: [
      { name: 'Capabilities', href: '#features' },
      { name: 'Pricing', href: '#pricing' },
      { name: 'Documentation', href: '#docs' },
      { name: 'Changelog', href: '#changelog' },
    ],
    resources: [
      { name: 'Blog', href: '#blog' },
      { name: 'Guides', href: '#guides' },
      { name: 'API Docs', href: '#api' },
      { name: 'Status', href: '#status' },
    ],
    company: [
      { name: 'About', href: '#about' },
      { name: 'Careers', href: '#careers' },
      { name: 'Contact', href: '#contact' },
    ],
  };

  const socials = [
    { icon: Github, href: 'https://github.com/ibonon/Adversum', label: 'GitHub' },
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
                <Shield className="w-6 h-6 text-primary relative z-10" />
              </div>
              <span className="text-xl font-semibold">Adversum</span>
            </a>
            <p className="text-sm text-muted-foreground mb-6 max-w-xs leading-relaxed">
              Next-generation application and smart contract security powered by Rust, NVIDIA Nemotron, and Z3 Formal Verification.
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
            <h4 className="text-sm font-semibold mb-4 uppercase tracking-wide">Product</h4>
            <ul className="space-y-3">
              {(links.product || []).map((link, i) => (
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
            <h4 className="text-sm font-semibold mb-4 uppercase tracking-wide">Resources</h4>
            <ul className="space-y-3">
              {(links.resources || []).map((link, i) => (
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
            <h4 className="text-sm font-semibold mb-4 uppercase tracking-wide">Company</h4>
            <ul className="space-y-3">
              {(links.company || []).map((link, i) => (
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
            © 2026 Adversum. All rights reserved.
          </p>
          <div className="flex items-center gap-6 text-sm text-muted-foreground">
            <a href="#" className="hover:text-foreground transition-colors">Privacy Policy</a>
            <a href="#" className="hover:text-foreground transition-colors">Terms of Service</a>
            <a href="#" className="hover:text-foreground transition-colors">Security Policy</a>
          </div>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
