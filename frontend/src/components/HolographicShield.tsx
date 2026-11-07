import { useRef, useMemo } from 'react';
import { Canvas, useFrame } from '@react-three/fiber';
import { Icosahedron, Torus, Sphere } from '@react-three/drei';
import * as THREE from 'three';

export type OrbState = 'idle' | 'scanning' | 'completed' | 'failed';

export interface HolographicShieldProps {
  state?: OrbState;
  hasCriticalFindings?: boolean;
  pulse?: number;
}

interface ShieldCoreProps {
  state: OrbState;
  hasCriticalFindings: boolean;
  pulse: number;
}

const ShieldCore = ({ state, hasCriticalFindings, pulse }: ShieldCoreProps) => {
  const groupRef = useRef<THREE.Group>(null);
  const coreRef = useRef<THREE.Mesh>(null);
  const ring1Ref = useRef<THREE.Mesh>(null);
  const ring2Ref = useRef<THREE.Mesh>(null);
  const ring3Ref = useRef<THREE.Mesh>(null);

  // Speed multiplier based on real backend state
  const speed = state === 'scanning' ? 2.6 : state === 'failed' ? 0.4 : 1.0;

  useFrame((sceneState) => {
    const t = sceneState.clock.elapsedTime;
    if (groupRef.current) {
      groupRef.current.rotation.y = t * 0.2 * speed;
    }
    if (coreRef.current) {
      let scaleOffset = 0;
      if (state === 'scanning') {
        scaleOffset = Math.sin(t * 5) * 0.12;
      } else if (state === 'failed') {
        scaleOffset = -0.05;
      } else {
        scaleOffset = Math.sin(t * 2) * 0.05 + pulse * 0.2;
      }
      coreRef.current.scale.setScalar(1 + scaleOffset);
    }
    if (ring1Ref.current) {
      ring1Ref.current.rotation.x = t * 0.5 * speed;
      ring1Ref.current.rotation.y = t * 0.3 * speed;
    }
    if (ring2Ref.current) {
      ring2Ref.current.rotation.x = -t * 0.4 * speed;
      ring2Ref.current.rotation.z = t * 0.6 * speed;
    }
    if (ring3Ref.current) {
      ring3Ref.current.rotation.y = t * 0.7 * speed;
      ring3Ref.current.rotation.z = -t * 0.3 * speed;
    }
  });

  // Color palette driven strictly by real state
  let primaryColor = '#00d4ff';
  let accentColor = '#a855f7';
  let emissiveIntensity = 0.5 + pulse;

  if (state === 'scanning') {
    primaryColor = '#00e5ff';
    accentColor = '#c084fc';
    emissiveIntensity = 1.3;
  } else if (state === 'completed') {
    if (hasCriticalFindings) {
      primaryColor = '#ef4444';
      accentColor = '#f59e0b';
      emissiveIntensity = 0.9;
    } else {
      primaryColor = '#10b981';
      accentColor = '#00d4ff';
      emissiveIntensity = 0.8;
    }
  } else if (state === 'failed') {
    primaryColor = '#dc2626';
    accentColor = '#7f1d1d';
    emissiveIntensity = 0.6;
  }

  return (
    <group ref={groupRef}>
      {/* Core */}
      <Icosahedron ref={coreRef} args={[1, 2]}>
        <meshStandardMaterial
          color={primaryColor}
          emissive={primaryColor}
          emissiveIntensity={emissiveIntensity}
          roughness={0.1}
          metalness={0.9}
          wireframe
        />
      </Icosahedron>

      {/* Inner glowing core */}
      <Sphere args={[0.5, 32, 32]}>
        <meshBasicMaterial
          color={primaryColor}
          transparent
          opacity={state === 'scanning' ? 0.6 : 0.3 + pulse * 0.4}
        />
      </Sphere>

      {/* Orbiting rings */}
      <Torus ref={ring1Ref} args={[1.6, 0.02, 16, 100]}>
        <meshBasicMaterial color={primaryColor} transparent opacity={0.65} />
      </Torus>
      <Torus ref={ring2Ref} args={[1.9, 0.02, 16, 100]}>
        <meshBasicMaterial color={accentColor} transparent opacity={0.55} />
      </Torus>
      <Torus ref={ring3Ref} args={[2.2, 0.015, 16, 100]}>
        <meshBasicMaterial color={primaryColor} transparent opacity={0.4} />
      </Torus>
    </group>
  );
};

const OrbitingParticles = ({ state, hasCriticalFindings }: { state: OrbState; hasCriticalFindings: boolean }) => {
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

  const speed = state === 'scanning' ? 2.5 : 1.0;

  useFrame((sceneState) => {
    if (pointsRef.current) {
      pointsRef.current.rotation.y = sceneState.clock.elapsedTime * 0.1 * speed;
      pointsRef.current.rotation.x = sceneState.clock.elapsedTime * 0.05 * speed;
    }
  });

  const particleColor =
    state === 'completed' && hasCriticalFindings
      ? '#f59e0b'
      : state === 'failed'
      ? '#ef4444'
      : '#00d4ff';

  return (
    <points ref={pointsRef}>
      <bufferGeometry>
        <bufferAttribute attach="attributes-position" count={count} array={positions} itemSize={3} />
      </bufferGeometry>
      <pointsMaterial size={0.04} color={particleColor} transparent opacity={0.8} sizeAttenuation />
    </points>
  );
};

const HolographicShield = ({
  state = 'idle',
  hasCriticalFindings = false,
  pulse = 0,
}: HolographicShieldProps) => {
  const lightColor =
    state === 'completed' && hasCriticalFindings
      ? '#f59e0b'
      : state === 'failed'
      ? '#ef4444'
      : '#00d4ff';

  return (
    <Canvas camera={{ position: [0, 0, 6], fov: 45 }} dpr={[1, 2]} gl={{ antialias: true, alpha: true }}>
      <ambientLight intensity={0.4} />
      <pointLight position={[5, 5, 5]} intensity={state === 'scanning' ? 1.5 : 1} color={lightColor} />
      <pointLight position={[-5, -5, -5]} intensity={0.6} color="#a855f7" />
      <ShieldCore state={state} hasCriticalFindings={hasCriticalFindings} pulse={pulse} />
      <OrbitingParticles state={state} hasCriticalFindings={hasCriticalFindings} />
    </Canvas>
  );
};

export default HolographicShield;
