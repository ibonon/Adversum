import Navbar from '@/components/Navbar';
import HeroSection from '@/components/HeroSection';
import FeaturesSection from '@/components/FeaturesSection';
import LiveSimulation from '@/components/LiveSimulation';
import HowItWorksSection from '@/components/HowItWorksSection';
import DashboardPreview from '@/components/DashboardPreview';
import PricingSection from '@/components/PricingSection';
import CTASection from '@/components/CTASection';
import Footer from '@/components/Footer';
import CustomCursor from '@/components/CustomCursor';
import ErrorBoundary from '@/components/ErrorBoundary';

const Index = () => {
  return (
    <div className="min-h-screen bg-background text-foreground overflow-x-hidden">
      <CustomCursor />
      <Navbar />
      <main>
        <HeroSection />
        <FeaturesSection />
        <ErrorBoundary>
          <LiveSimulation />
        </ErrorBoundary>
        <HowItWorksSection />
        <DashboardPreview />
        <PricingSection />
        <CTASection />
      </main>
      <Footer />
    </div>
  );
};

export default Index;
