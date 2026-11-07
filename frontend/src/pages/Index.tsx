import HeroSection from '@/components/HeroSection';

const Index = () => {
  return (
    <div className="min-h-screen bg-background text-foreground overflow-x-hidden flex flex-col items-center justify-start">
      <main className="w-full">
        <HeroSection />
      </main>
    </div>
  );
};

export default Index;
