"use client";

import { useEffect, useRef, useState } from "react";
import { motion, useMotionValue, useSpring, useReducedMotion } from "framer-motion";

interface ThreatDetectionAnimationProps {
  isActive: boolean;
  position: { x: number; y: number };
  onComplete?: () => void;
  className?: string;
}

interface ScanParticle {
  id: number;
  x: number;
  y: number;
  delay: number;
  duration: number;
  size: number;
}

export function ThreatDetectionAnimation({
  isActive,
  position,
  onComplete,
  className = "",
}: ThreatDetectionAnimationProps) {
  const prefersReducedMotion = useReducedMotion();
  const [particles, setParticles] = useState<ScanParticle[]>([]);
  const [scanLineProgress, setScanLineProgress] = useState(0);
  const [showTarget, setShowTarget] = useState(false);
  const [pulseScale, setPulseScale] = useState(1);
  const animationRef = useRef<NodeJS.Timeout | null>(null);
  const particleRef = useRef<NodeJS.Timeout | null>(null);
  const pulseRef = useRef<NodeJS.Timeout | null>(null);

  const scanProgress = useMotionValue(0);
  const springProgress = useSpring(scanProgress, { stiffness: 100, damping: 20 });

  const generateParticles = () => {
    const newParticles: ScanParticle[] = [];
    for (let i = 0; i < 12; i++) {
      newParticles.push({
        id: i,
        x: -10 + Math.random() * 20,
        y: 20 + Math.random() * 60,
        delay: Math.random() * 500,
        duration: 800 + Math.random() * 400,
        size: 2 + Math.random() * 3,
      });
    }
    setParticles(newParticles);
  };

  const startScanAnimation = () => {
    if (prefersReducedMotion) {
      onComplete?.();
      return;
    }

    generateParticles();
    setScanLineProgress(0);
    setShowTarget(false);

    scanProgress.set(0);
    scanProgress.set(1);

    const scanDuration = 1500;
    const steps = 60;
    const stepTime = scanDuration / steps;

    let currentStep = 0;
    const animateScan = () => {
      currentStep++;
      setScanLineProgress(currentStep / steps);

      if (currentStep >= steps) {
        setShowTarget(true);
        setTimeout(() => {
          onComplete?.();
          setShowTarget(false);
        }, 800);
        return;
      }

      animationRef.current = setTimeout(animateScan, stepTime);
    };

    animateScan();

    particleRef.current = setTimeout(() => {
      setParticles([]);
    }, scanDuration + 500);

    pulseRef.current = setInterval(() => {
      setPulseScale((prev) => (prev === 1 ? 1.3 : 1));
    }, 400);
  };

  useEffect(() => {
    if (isActive) {
      startScanAnimation();
    }

    return () => {
      if (animationRef.current) clearTimeout(animationRef.current);
      if (particleRef.current) clearTimeout(particleRef.current);
      if (pulseRef.current) clearInterval(pulseRef.current);
    };
  }, [isActive, prefersReducedMotion]);

  if (prefersReducedMotion || !isActive) {
    return null;
  }

  return (
    <div
      className={`threat-detection-overlay ${className}`}
      style={{
        left: `${position.x}%`,
        bottom: `${position.y}%`,
        pointerEvents: "none",
        zIndex: 10,
      } as React.CSSProperties}
    >
      <motion.div
        className="scan-cone"
        initial={{ scaleY: 0, opacity: 0 }}
        animate={{ scaleY: 1, opacity: 0.3 }}
        exit={{ scaleY: 0, opacity: 0 }}
        transition={{ duration: 0.8, ease: "easeOut" }}
        style={{
          transformOrigin: "top center",
          height: `${scanLineProgress * 120}px`,
        } as React.CSSProperties}
      />

      <motion.div
        className="scan-line"
        style={{
          top: `${scanLineProgress * 120}px`,
          opacity: scanLineProgress > 0 && scanLineProgress < 1 ? 1 : 0,
        } as React.CSSProperties}
      />

      {particles.map((particle) => (
        <motion.div
          key={particle.id}
          className="scan-particle"
          initial={{ opacity: 0, scale: 0, y: 0 }}
          animate={{ opacity: 1, scale: 1, y: -40 }}
          exit={{ opacity: 0, scale: 0 }}
          transition={{
            delay: particle.delay / 1000,
            duration: particle.duration / 1000,
            ease: "easeOut",
          }}
          style={{
            left: `calc(50% + ${particle.x}px)`,
            bottom: `${particle.y}%`,
            width: `${particle.size}px`,
            height: `${particle.size}px`,
          } as React.CSSProperties}
        />
      ))}

      <motion.div
        className="target-marker"
        initial={{ scale: 0, opacity: 0, rotate: -45 }}
        animate={{ scale: pulseScale, opacity: 1, rotate: 0 }}
        exit={{ scale: 0, opacity: 0 }}
        transition={{ duration: 0.3 }}
        style={{ transformOrigin: "center" } as React.CSSProperties}
      >
        <div className="target-ring" />
        <div className="target-ring" style={{ animationDelay: "0.2s" }} />
        <div className="target-ring" style={{ animationDelay: "0.4s" }} />
        <div className="target-crosshair" />
      </motion.div>

      <motion.div
        className="detection-pulse"
        initial={{ scale: 0, opacity: 0.6 }}
        animate={{ scale: 3, opacity: 0 }}
        transition={{ duration: 1, ease: "easeOut" }}
      />
    </div>
  );
}

export function AmbientScanEffect({ className = "" }: { className?: string }) {
  const prefersReducedMotion = useReducedMotion();
  const [scanLines, setScanLines] = useState<number[]>([]);

  useEffect(() => {
    if (prefersReducedMotion) return;

    const lines = Array.from({ length: 3 }, (_, i) => i * 120 + Math.random() * 60);
    setScanLines(lines);

    const interval = setInterval(() => {
      setScanLines((prev) =>
        prev.map((line) => {
          const newLine = line + 2;
          return newLine > window.innerHeight + 100 ? -100 : newLine;
        })
      );
    }, 50);

    return () => clearInterval(interval);
  }, [prefersReducedMotion]);

  if (prefersReducedMotion) return null;

  return (
    <div className={`ambient-scan-container ${className}`} aria-hidden="true">
      {scanLines.map((line, index) => (
        <motion.div
          key={index}
          className="ambient-scan-line"
          style={{ top: `${line}px` } as React.CSSProperties}
          initial={{ opacity: 0 }}
          animate={{ opacity: [0, 0.4, 0] }}
          transition={{ duration: 8, repeat: Infinity, delay: index * 2.5 }}
        />
      ))}
    </div>
  );
}