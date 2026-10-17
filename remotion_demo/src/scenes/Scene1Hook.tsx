import React from "react";
import { AbsoluteFill, interpolate, spring, useCurrentFrame, useVideoConfig } from "remotion";
import { theme } from "../theme";

export const Scene1Hook: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  // Entrance spring for main headline
  const titleEntrance = spring({
    frame,
    fps,
    config: { damping: 14, mass: 0.6, stiffness: 120 },
  });

  const titleScale = interpolate(titleEntrance, [0, 1], [0.85, 1]);
  const titleOpacity = interpolate(titleEntrance, [0, 1], [0, 1]);

  // Entrance for danger callout
  const dangerEntrance = spring({
    frame: frame - 45,
    fps,
    config: { damping: 12, mass: 0.5, stiffness: 140 },
  });

  const dangerScale = interpolate(dangerEntrance, [0, 1], [0.9, 1]);
  const dangerOpacity = interpolate(dangerEntrance, [0, 1], [0, 1]);

  // Subtitle fade
  const subOpacity = interpolate(frame, [80, 105], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const subY = interpolate(frame, [80, 105], [20, 0], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });

  // Pulse effect
  const pulse = Math.sin(frame / 12) * 0.08;

  return (
    <AbsoluteFill
      style={{
        backgroundColor: theme.bg,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        fontFamily: theme.fontSans,
        color: theme.textMain,
        padding: 80,
      }}
    >
      {/* Background Cyber Grid */}
      <div
        style={{
          position: "absolute",
          inset: 0,
          backgroundImage: `radial-gradient(circle at 50% 50%, rgba(239, 68, 68, 0.12) 0%, transparent 60%), linear-gradient(rgba(255,255,255,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.03) 1px, transparent 1px)`,
          backgroundSize: "100% 100%, 48px 48px, 48px 48px",
        }}
      />

      <div
        style={{
          position: "relative",
          zIndex: 10,
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          textAlign: "center",
          maxWidth: 1200,
        }}
      >
        {/* Warning Pill */}
        <div
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: 10,
            padding: "8px 22px",
            borderRadius: 9999,
            backgroundColor: "rgba(239, 68, 68, 0.15)",
            border: "1px solid rgba(239, 68, 68, 0.4)",
            color: "#fca5a5",
            fontSize: 22,
            fontWeight: 600,
            letterSpacing: "0.05em",
            marginBottom: 32,
            transform: `scale(${1 + pulse})`,
          }}
        >
          <span>⚠️</span>
          <span>AUTONOMOUS AGENT SECURITY ALERT</span>
        </div>

        {/* Main Headline */}
        <h1
          style={{
            fontSize: 78,
            fontWeight: 800,
            lineHeight: 1.15,
            letterSpacing: "-0.03em",
            marginBottom: 24,
            transform: `scale(${titleScale})`,
            opacity: titleOpacity,
            textShadow: "0 0 40px rgba(255,255,255,0.2)",
          }}
        >
          AI Agents Are Given Full System Access.
        </h1>

        {/* Dangerous Callout */}
        <div
          style={{
            transform: `scale(${dangerScale})`,
            opacity: dangerOpacity,
            fontSize: 72,
            fontWeight: 900,
            letterSpacing: "-0.03em",
            color: theme.crimson,
            textShadow: `0 0 50px ${theme.crimsonGlow}`,
            marginBottom: 32,
          }}
        >
          With ZERO Security Boundaries.
        </div>

        {/* Explanatory subtitle */}
        <p
          style={{
            opacity: subOpacity,
            transform: `translateY(${subY}px)`,
            fontSize: 28,
            color: theme.textMuted,
            maxWidth: 900,
            lineHeight: 1.5,
          }}
        >
          When an agent reads untrusted web data, an indirect prompt injection
          can hijack tool execution and drain credentials in a single step.
        </p>
      </div>
    </AbsoluteFill>
  );
};
