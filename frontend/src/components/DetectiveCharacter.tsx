"use client";

import { useEffect, useRef, useState } from "react";
import { motion, useReducedMotion } from "framer-motion";

interface DetectiveCharacterProps {
  className?: string;
  initialPosition?: { x: number; y: number };
}

const ANIMATION_STATES = {
  WALK: "walk",
  STOP: "stop",
  INSPECT: "inspect",
  DETECT: "detect",
  ALERT: "alert",
  IDLE: "idle",
} as const;

type AnimationState = (typeof ANIMATION_STATES)[keyof typeof ANIMATION_STATES];

const STATE_DURATIONS: Record<AnimationState, number> = {
  walk: 3000,
  stop: 1200,
  inspect: 2000,
  detect: 800,
  alert: 1500,
  idle: 4000,
};

const NOTIFICATION_MESSAGES = [
  { text: "THREAT DETECTED", type: "critical" as const },
  { text: "SCANNING...", type: "info" as const },
  { text: "ANALYZING PAYLOAD", type: "info" as const },
  { text: "SUSPICIOUS BEHAVIOR", type: "critical" as const },
  { text: "ENTROPY: 7.91", type: "info" as const },
  { text: "C2 BEACON FOUND", type: "critical" as const },
];

export function DetectiveCharacter({
  className = "",
  initialPosition = { x: 5, y: 85 },
}: DetectiveCharacterProps) {
  const prefersReducedMotion = useReducedMotion();
  const [currentState, setCurrentState] = useState<AnimationState>(ANIMATION_STATES.IDLE);
  const [notification, setNotification] = useState<{ text: string; type: "critical" | "info" } | null>(null);
  const [position, setPosition] = useState(initialPosition);
  const [direction, setDirection] = useState<1 | -1>(1);
  const characterRef = useRef<HTMLDivElement>(null);
  const stateTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const cycleTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const notificationTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  const runStateCycle = () => {
    if (prefersReducedMotion) return;

    const states: AnimationState[] = [
      ANIMATION_STATES.WALK,
      ANIMATION_STATES.STOP,
      ANIMATION_STATES.INSPECT,
      ANIMATION_STATES.DETECT,
      ANIMATION_STATES.ALERT,
      ANIMATION_STATES.IDLE,
    ];

    let stateIndex = 0;

    const executeState = (state: AnimationState) => {
      setCurrentState(state);
      const duration = STATE_DURATIONS[state];

      if (state === ANIMATION_STATES.WALK) {
        setPosition((prev) => ({
          x: Math.max(3, Math.min(85, prev.x + (direction === 1 ? 12 : -12))),
          y: prev.y,
        }));
      }

      if (state === ANIMATION_STATES.INSPECT) {
        setNotification({ text: "SCANNING...", type: "info" });
        notificationTimeoutRef.current = setTimeout(() => setNotification(null), 2500);
      }

      if (state === ANIMATION_STATES.DETECT) {
        const msg = NOTIFICATION_MESSAGES[Math.floor(Math.random() * NOTIFICATION_MESSAGES.length)];
        setNotification(msg);
        notificationTimeoutRef.current = setTimeout(() => setNotification(null), 2500);
      }

      if (state === ANIMATION_STATES.ALERT) {
        setDirection((prev) => (prev === 1 ? -1 : 1));
      }

      stateTimeoutRef.current = setTimeout(() => {
        stateIndex = (stateIndex + 1) % states.length;
        executeState(states[stateIndex]);
      }, duration);
    };

    executeState(states[stateIndex]);
  };

  useEffect(() => {
    if (prefersReducedMotion) {
      setCurrentState(ANIMATION_STATES.IDLE);
      return;
    }

    const initialDelay = setTimeout(runStateCycle, 1000);

    cycleTimeoutRef.current = setInterval(() => {
      if (stateTimeoutRef.current) clearTimeout(stateTimeoutRef.current);
      setCurrentState(ANIMATION_STATES.IDLE);
      setTimeout(runStateCycle, STATE_DURATIONS.idle);
    }, 15000);

    return () => {
      clearTimeout(initialDelay);
      if (stateTimeoutRef.current) clearTimeout(stateTimeoutRef.current);
      if (cycleTimeoutRef.current) clearInterval(cycleTimeoutRef.current);
      if (notificationTimeoutRef.current) clearTimeout(notificationTimeoutRef.current);
    };
  }, [prefersReducedMotion, direction]);

  const getCharacterClasses = () => {
    const classes = ["detective-char"];
    classes.push(currentState);
    if (direction === -1) classes.push("flip");
    return classes.join(" ");
  };

  return (
    <motion.div
      ref={characterRef}
      className={`detective-wrapper ${className}`}
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 1 }}
      style={{ left: `${position.x}%`, bottom: `${position.y}%` } as React.CSSProperties}
    >
      <div className="d-ground-shadow" />

      <div className={getCharacterClasses()}>
        <img
          src="/detective-character.png"
          alt="Cyber Detective"
          className="detective-img"
        />
        <div className="detective-glow" />
        <div className="detective-beam" />
        <div className="detective-particles">
          <div className="d-particle" />
          <div className="d-particle" />
          <div className="d-particle" />
          <div className="d-particle" />
          <div className="d-particle" />
        </div>
        <div className="detective-target" />
      </div>

      {notification && (
        <motion.div
          className={`d-notif ${notification.type === "info" ? "info-notif" : ""}`}
          initial={{ opacity: 0, y: 10, scale: 0.9 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          exit={{ opacity: 0, y: -10, scale: 0.9 }}
          transition={{ duration: 0.3 }}
        >
          <span className="d-notif-dot" />
          <span>{notification.text}</span>
        </motion.div>
      )}
    </motion.div>
  );
}