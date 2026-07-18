import { useRef, useMemo } from 'react';
import { Canvas, useFrame } from '@react-three/fiber';
import { Icosahedron, Torus, Sphere } from '@react-three/drei';
import * as THREE from 'three';

const ShieldCore = ({ pulse }: { pulse: number }) => {
  const groupRef = useRef<THREE.Group>(null);
  const coreRef = useRef<THREE.Mesh>(null);
  const ring1Ref = useRef<THREE.Mesh>(null);
  const ring2Ref = useRef<THREE.Mesh>(null);
  const ring3Ref = useRef<THREE.Mesh>(null);

  useFrame((state) => {
    const t = state.clock.elapsedTime;
    if (groupRef.current) {
      groupRef.current.rotation.y = t * 0.2;
    }
    if (coreRef.current) {
      const s = 1 + Math.sin(t * 2) * 0.05 + pulse * 0.3;
      coreRef.current.scale.setScalar(s);
    }
    if (ring1Ref.current) {
      ring1Ref.current.rotation.x = t * 0.5;
      ring1Ref.current.rotation.y = t * 0.3;
    }
    if (ring2Ref.current) {
      ring2Ref.current.rotation.x = -t * 0.4;
      ring2Ref.current.rotation.z = t * 0.6;
    }
    if (ring3Ref.current) {
      ring3Ref.current.rotation.y = t * 0.7;
      ring3Ref.current.rotation.z = -t * 0.3;
    }
  });

  return (
    <group ref={groupRef}>
      {/* Core */}
      <Icosahedron ref={coreRef} args={[1, 2]}>
        <meshStandardMaterial
          color="#00d4ff"
          emissive="#00d4ff"
          emissiveIntensity={0.5 + pulse}
          roughness={0.1}
          metalness={0.9}
          wireframe
        />
      </Icosahedron>

      {/* Inner glowing core */}
      <Sphere args={[0.5, 32, 32]}>
        <meshBasicMaterial color="#00d4ff" transparent opacity={0.3 + pulse * 0.5} />
      </Sphere>

      {/* Orbiting rings */}
      <Torus ref={ring1Ref} args={[1.6, 0.02, 16, 100]}>
        <meshBasicMaterial color="#00d4ff" transparent opacity={0.6} />
      </Torus>
      <Torus ref={ring2Ref} args={[1.9, 0.02, 16, 100]}>
        <meshBasicMaterial color="#a855f7" transparent opacity={0.5} />
      </Torus>
      <Torus ref={ring3Ref} args={[2.2, 0.015, 16, 100]}>
        <meshBasicMaterial color="#00d4ff" transparent opacity={0.4} />
      </Torus>
    </group>
  );
};

const OrbitingParticles = () => {
  const pointsRef = useRef<THREE.Points>(null);
  const count = 200;

  const positions = useMemo(() => {
    const pos = new Float32Array(count * 3);
    for (let i = 0; i < count; i++) {
      const radius = 2.5 + Math.random() * 1.5;
      const theta = Math.random() * Math.PI * 2;
      const phi = Math.acos(2 * Math.random() - 1);
      pos[i * 3] = radius * Math.sin(phi) * Math.cos(theta);
      pos[i * 3 + 1] = radius * Math.sin(phi) * Math.sin(theta);
      pos[i * 3 + 2] = radius * Math.cos(phi);
    }
    return pos;
  }, []);

  useFrame((state) => {
    if (pointsRef.current) {
      pointsRef.current.rotation.y = state.clock.elapsedTime * 0.1;
      pointsRef.current.rotation.x = state.clock.elapsedTime * 0.05;
    }
  });

  return (
    <points ref={pointsRef}>
      <bufferGeometry>
        <bufferAttribute attach="attributes-position" count={count} array={positions} itemSize={3} />
      </bufferGeometry>
      <pointsMaterial size={0.04} color="#00d4ff" transparent opacity={0.8} sizeAttenuation />
    </points>
  );
};

const HolographicShield = ({ pulse = 0 }: { pulse?: number }) => {
  return (
    <Canvas camera={{ position: [0, 0, 6], fov: 45 }} dpr={[1, 2]} gl={{ antialias: true, alpha: true }}>
      <ambientLight intensity={0.4} />
      <pointLight position={[5, 5, 5]} intensity={1} color="#00d4ff" />
      <pointLight position={[-5, -5, -5]} intensity={0.6} color="#a855f7" />
      <ShieldCore pulse={pulse} />
      <OrbitingParticles />
    </Canvas>
  );
};

export default HolographicShield;
