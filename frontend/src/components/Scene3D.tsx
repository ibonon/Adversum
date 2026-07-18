import { useRef, useMemo } from 'react';
import { Canvas, useFrame } from '@react-three/fiber';
import { Float, MeshDistortMaterial, Sphere, Torus, Box, Icosahedron } from '@react-three/drei';
import * as THREE from 'three';

const AnimatedSphere = ({ position, color, speed = 1, distort = 0.3, scale = 1 }: {
  position: [number, number, number];
  color: string;
  speed?: number;
  distort?: number;
  scale?: number;
}) => {
  const meshRef = useRef<THREE.Mesh>(null);

  useFrame((state) => {
    if (meshRef.current) {
      meshRef.current.rotation.x = state.clock.elapsedTime * 0.1 * speed;
      meshRef.current.rotation.y = state.clock.elapsedTime * 0.15 * speed;
    }
  });

  return (
    <Float speed={2} rotationIntensity={0.5} floatIntensity={1}>
      <Sphere ref={meshRef} args={[1, 64, 64]} position={position} scale={scale}>
        <MeshDistortMaterial
          color={color}
          attach="material"
          distort={distort}
          speed={2}
          roughness={0.1}
          metalness={0.8}
        />
      </Sphere>
    </Float>
  );
};

const AnimatedTorus = ({ position, color, scale = 1 }: {
  position: [number, number, number];
  color: string;
  scale?: number;
}) => {
  const meshRef = useRef<THREE.Mesh>(null);

  useFrame((state) => {
    if (meshRef.current) {
      meshRef.current.rotation.x = state.clock.elapsedTime * 0.2;
      meshRef.current.rotation.y = state.clock.elapsedTime * 0.3;
    }
  });

  return (
    <Float speed={1.5} rotationIntensity={0.3} floatIntensity={0.8}>
      <Torus ref={meshRef} args={[1, 0.3, 32, 100]} position={position} scale={scale}>
        <meshStandardMaterial
          color={color}
          roughness={0.2}
          metalness={0.9}
          transparent
          opacity={0.8}
        />
      </Torus>
    </Float>
  );
};

const FloatingCube = ({ position, color, scale = 1 }: {
  position: [number, number, number];
  color: string;
  scale?: number;
}) => {
  const meshRef = useRef<THREE.Mesh>(null);

  useFrame((state) => {
    if (meshRef.current) {
      meshRef.current.rotation.x = state.clock.elapsedTime * 0.15;
      meshRef.current.rotation.y = state.clock.elapsedTime * 0.2;
    }
  });

  return (
    <Float speed={1} rotationIntensity={0.4} floatIntensity={0.6}>
      <Box ref={meshRef} args={[1, 1, 1]} position={position} scale={scale}>
        <meshStandardMaterial
          color={color}
          roughness={0.1}
          metalness={0.95}
          transparent
          opacity={0.7}
        />
      </Box>
    </Float>
  );
};

const FloatingIcosahedron = ({ position, color, scale = 1 }: {
  position: [number, number, number];
  color: string;
  scale?: number;
}) => {
  const meshRef = useRef<THREE.Mesh>(null);

  useFrame((state) => {
    if (meshRef.current) {
      meshRef.current.rotation.x = state.clock.elapsedTime * 0.1;
      meshRef.current.rotation.z = state.clock.elapsedTime * 0.15;
    }
  });

  return (
    <Float speed={2.5} rotationIntensity={0.6} floatIntensity={1.2}>
      <Icosahedron ref={meshRef} args={[1, 1]} position={position} scale={scale}>
        <meshStandardMaterial
          color={color}
          roughness={0.15}
          metalness={0.85}
          wireframe
        />
      </Icosahedron>
    </Float>
  );
};

const ParticleField = () => {
  const count = 500;
  const meshRef = useRef<THREE.Points>(null);

  const particles = useMemo(() => {
    const positions = new Float32Array(count * 3);
    for (let i = 0; i < count; i++) {
      positions[i * 3] = (Math.random() - 0.5) * 30;
      positions[i * 3 + 1] = (Math.random() - 0.5) * 30;
      positions[i * 3 + 2] = (Math.random() - 0.5) * 30;
    }
    return positions;
  }, []);

  useFrame((state) => {
    if (meshRef.current) {
      meshRef.current.rotation.y = state.clock.elapsedTime * 0.02;
      meshRef.current.rotation.x = state.clock.elapsedTime * 0.01;
    }
  });

  return (
    <points ref={meshRef}>
      <bufferGeometry>
        <bufferAttribute
          attach="attributes-position"
          count={count}
          array={particles}
          itemSize={3}
        />
      </bufferGeometry>
      <pointsMaterial
        size={0.03}
        color="#00d4ff"
        transparent
        opacity={0.6}
        sizeAttenuation
      />
    </points>
  );
};

const Scene3D = ({ variant = 'hero' }: { variant?: 'hero' | 'features' | 'cta' }) => {
  return (
    <div className="absolute inset-0 -z-10">
      <Canvas
        camera={{ position: [0, 0, 8], fov: 45 }}
        dpr={[1, 2]}
        gl={{ antialias: true, alpha: true }}
      >
        <ambientLight intensity={0.4} />
        <directionalLight position={[10, 10, 5]} intensity={1} />
        <pointLight position={[-10, -10, -5]} intensity={0.5} color="#a855f7" />
        <pointLight position={[10, -10, 5]} intensity={0.5} color="#00d4ff" />

        {variant === 'hero' && (
          <>
            <AnimatedSphere position={[-3.5, 1.5, -2]} color="#00d4ff" distort={0.4} scale={1.2} />
            <AnimatedSphere position={[4, -1, -3]} color="#a855f7" distort={0.3} scale={0.8} speed={0.7} />
            <AnimatedTorus position={[3.5, 2, -4]} color="#00d4ff" scale={0.6} />
            <FloatingCube position={[-4, -2, -2]} color="#a855f7" scale={0.5} />
            <FloatingIcosahedron position={[4.5, 0, -1]} color="#00d4ff" scale={0.4} />
            <ParticleField />
          </>
        )}

        {variant === 'features' && (
          <>
            <AnimatedSphere position={[-5, 0, -5]} color="#00d4ff" distort={0.2} scale={1.5} speed={0.5} />
            <AnimatedTorus position={[5, 1, -6]} color="#a855f7" scale={1} />
            <FloatingIcosahedron position={[0, -3, -4]} color="#10b981" scale={0.6} />
            <ParticleField />
          </>
        )}

        {variant === 'cta' && (
          <>
            <AnimatedSphere position={[0, 0, -3]} color="#00d4ff" distort={0.5} scale={2} speed={0.3} />
            <AnimatedTorus position={[-3, 2, -5]} color="#a855f7" scale={0.8} />
            <AnimatedTorus position={[3, -2, -5]} color="#10b981" scale={0.6} />
            <ParticleField />
          </>
        )}
      </Canvas>
    </div>
  );
};

export default Scene3D;
