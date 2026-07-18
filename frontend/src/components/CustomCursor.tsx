import { useEffect, useState, useRef } from 'react';

const CustomCursor = () => {
  const [position, setPosition] = useState({ x: -100, y: -100 });
  const [isHovering, setIsHovering] = useState(false);
  const [isClicking, setIsClicking] = useState(false);
  const [isVisible, setIsVisible] = useState(false);
  const trailRef = useRef({ x: -100, y: -100 });
  const trailPos = useRef({ x: -100, y: -100 });
  const rafRef = useRef<number>();

  useEffect(() => {
    // Hide on touch devices
    if ('ontouchstart' in window) return;

    const handleMouseMove = (e: MouseEvent) => {
      setPosition({ x: e.clientX, y: e.clientY });
      trailRef.current = { x: e.clientX, y: e.clientY };
      if (!isVisible) setIsVisible(true);
    };

    const handleMouseDown = () => setIsClicking(true);
    const handleMouseUp = () => setIsClicking(false);
    const handleMouseLeave = () => setIsVisible(false);
    const handleMouseEnter = () => setIsVisible(true);

    const handleHoverIn = (e: Event) => {
      const target = e.target as HTMLElement;
      if (target.closest('a, button, [role="button"], input, textarea, select, [data-cursor-hover]')) {
        setIsHovering(true);
      }
    };
    const handleHoverOut = (e: Event) => {
      const target = e.target as HTMLElement;
      if (target.closest('a, button, [role="button"], input, textarea, select, [data-cursor-hover]')) {
        setIsHovering(false);
      }
    };

    window.addEventListener('mousemove', handleMouseMove);
    window.addEventListener('mousedown', handleMouseDown);
    window.addEventListener('mouseup', handleMouseUp);
    document.body.addEventListener('mouseleave', handleMouseLeave);
    document.body.addEventListener('mouseenter', handleMouseEnter);
    document.addEventListener('mouseover', handleHoverIn);
    document.addEventListener('mouseout', handleHoverOut);

    // Smooth trail
    const animate = () => {
      trailPos.current.x += (trailRef.current.x - trailPos.current.x) * 0.15;
      trailPos.current.y += (trailRef.current.y - trailPos.current.y) * 0.15;
      const trail = document.getElementById('cursor-trail');
      if (trail) {
        trail.style.transform = `translate3d(${trailPos.current.x}px, ${trailPos.current.y}px, 0) translate(-50%, -50%)`;
      }
      rafRef.current = requestAnimationFrame(animate);
    };
    rafRef.current = requestAnimationFrame(animate);

    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('mousedown', handleMouseDown);
      window.removeEventListener('mouseup', handleMouseUp);
      document.body.removeEventListener('mouseleave', handleMouseLeave);
      document.body.removeEventListener('mouseenter', handleMouseEnter);
      document.removeEventListener('mouseover', handleHoverIn);
      document.removeEventListener('mouseout', handleHoverOut);
      if (rafRef.current) cancelAnimationFrame(rafRef.current);
    };
  }, [isVisible]);

  if ('ontouchstart' in window) return null;

  return (
    <>
      {/* Outer glow trail */}
      <div
        id="cursor-trail"
        className="pointer-events-none fixed top-0 left-0 z-[9999] hidden md:block"
        style={{
          width: isHovering ? '80px' : '40px',
          height: isHovering ? '80px' : '40px',
          borderRadius: '50%',
          background: `radial-gradient(circle, hsl(var(--primary) / 0.25) 0%, hsl(var(--primary) / 0) 70%)`,
          transition: 'width 0.3s ease, height 0.3s ease, opacity 0.3s ease',
          opacity: isVisible ? 1 : 0,
        }}
      />
      {/* Inner dot */}
      <div
        className="pointer-events-none fixed top-0 left-0 z-[9999] hidden md:block"
        style={{
          transform: `translate3d(${position.x}px, ${position.y}px, 0) translate(-50%, -50%) scale(${
            isClicking ? 0.6 : isHovering ? 1.6 : 1
          })`,
          width: '8px',
          height: '8px',
          borderRadius: '50%',
          background: 'hsl(var(--primary))',
          boxShadow: '0 0 12px hsl(var(--primary)), 0 0 24px hsl(var(--primary) / 0.5)',
          transition: 'transform 0.15s ease, opacity 0.3s ease',
          opacity: isVisible ? 1 : 0,
        }}
      />
    </>
  );
};

export default CustomCursor;
