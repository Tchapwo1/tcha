import React from "react";
import { AbsoluteFill, interpolate, spring, useCurrentFrame, useVideoConfig } from "remotion";
import { theme } from "../theme";

export const Scene4Victory: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  // Entrance spring for main stats container
  const statsEntrance = spring({
    frame,
    fps,
    config: { damping: 14, mass: 0.6, stiffness: 120 },
  });
  const statsScale = interpolate(statsEntrance, [0, 1], [0.85, 1]);
  const statsOpacity = interpolate(statsEntrance, [0, 1], [0, 1]);

  // CTA terminal spring
  const ctaEntrance = spring({
    frame: frame - 40,
    fps,
    config: { damping: 12, mass: 0.5, stiffness: 130 },
  });
  const ctaScale = interpolate(ctaEntrance, [0, 1], [0.9, 1]);
  const ctaOpacity = interpolate(ctaEntrance, [0, 1], [0, 1]);

  // Badges fade-in
  const badgesOpacity = interpolate(frame, [70, 95], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });

  const glowPulse = 1 + Math.sin(frame / 10) * 0.05;

  return (
    <AbsoluteFill
      style={{
        backgroundColor: theme.bg,
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        fontFamily: theme.fontSans,
        color: theme.textMain,
        padding: 60,
      }}
    >
      {/* Background Cyber Glow */}
      <div
        style={{
          position: "absolute",
          width: 1000,
          height: 1000,
          borderRadius: "50%",
          background: "radial-gradient(circle, rgba(6, 182, 212, 0.12) 0%, transparent 65%)",
          filter: "blur(100px)",
        }}
      />

      {/* Main Title */}
      <div
        style={{
          fontSize: 32,
          fontWeight: 700,
          letterSpacing: "0.1em",
          color: theme.cyan,
          textTransform: "uppercase",
          marginBottom: 16,
        }}
      >
        Verified Red-Team Benchmark
      </div>

      {/* Benchmark Stats Card */}
      <div
        style={{
          display: "flex",
          gap: 32,
          backgroundColor: theme.cardBg,
          border: `1px solid ${theme.border}`,
          borderRadius: 20,
          padding: "32px 56px",
          boxShadow: "0 25px 60px rgba(0,0,0,0.6)",
          marginBottom: 44,
          transform: `scale(${statsScale})`,
          opacity: statsOpacity,
        }}
      >
        <div style={{ textAlign: "center", minWidth: 220 }}>
          <div
            style={{
              fontSize: 68,
              fontWeight: 900,
              color: theme.emerald,
              fontFamily: theme.fontMono,
              fontVariantNumeric: "tabular-nums",
              lineHeight: 1,
              marginBottom: 8,
              textShadow: `0 0 30px ${theme.emeraldGlow}`,
            }}
          >
            100 / 100
          </div>
          <div style={{ fontSize: 18, color: theme.textMuted, fontWeight: 600 }}>
            PROBES NEUTRALIZED
          </div>
        </div>

        <div style={{ width: 1, backgroundColor: theme.border }} />

        <div style={{ textAlign: "center", minWidth: 220 }}>
          <div
            style={{
              fontSize: 68,
              fontWeight: 900,
              color: theme.cyan,
              fontFamily: theme.fontMono,
              fontVariantNumeric: "tabular-nums",
              lineHeight: 1,
              marginBottom: 8,
              textShadow: `0 0 30px ${theme.cyanGlow}`,
            }}
          >
            100%
          </div>
          <div style={{ fontSize: 18, color: theme.textMuted, fontWeight: 600 }}>
            RESILIENCE (TIER A+)
          </div>
        </div>

        <div style={{ width: 1, backgroundColor: theme.border }} />

        <div style={{ textAlign: "center", minWidth: 220 }}>
          <div
            style={{
              fontSize: 68,
              fontWeight: 900,
              color: theme.violet,
              fontFamily: theme.fontMono,
              fontVariantNumeric: "tabular-nums",
              lineHeight: 1,
              marginBottom: 8,
            }}
          >
            &lt; 0.8ms
          </div>
          <div style={{ fontSize: 18, color: theme.textMuted, fontWeight: 600 }}>
            PROXY OVERHEAD
          </div>
        </div>
      </div>

      {/* 1-Command Onboarding CTA Box */}
      <div
        style={{
          width: 900,
          backgroundColor: "rgba(2, 6, 23, 0.9)",
          border: `2px solid ${theme.emerald}`,
          borderRadius: 16,
          padding: "24px 36px",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          boxShadow: `0 0 45px ${theme.emeraldGlow}`,
          transform: `scale(${ctaScale * glowPulse})`,
          opacity: ctaOpacity,
          marginBottom: 36,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          <span style={{ fontSize: 28, color: theme.emerald }}>$</span>
          <span
            style={{
              fontFamily: theme.fontMono,
              fontSize: 32,
              fontWeight: 800,
              color: "#ffffff",
              letterSpacing: "0.02em",
            }}
          >
            npx tcha audit
          </span>
        </div>
        <div
          style={{
            backgroundColor: theme.emerald,
            color: "#05070c",
            padding: "10px 20px",
            borderRadius: 8,
            fontWeight: 800,
            fontSize: 18,
            letterSpacing: "0.05em",
            textTransform: "uppercase",
          }}
        >
          1-Click Run
        </div>
      </div>

      {/* Badges & Repo link */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 24,
          opacity: badgesOpacity,
        }}
      >
        <div
          style={{
            fontSize: 20,
            color: theme.textMuted,
            display: "flex",
            alignItems: "center",
            gap: 12,
          }}
        >
          <span>⭐ Star on GitHub:</span>
          <span
            style={{
              color: theme.textMain,
              fontWeight: 700,
              fontFamily: theme.fontMono,
            }}
          >
            github.com/tchaprotection/tcha
          </span>
        </div>
        <div
          style={{
            padding: "6px 14px",
            backgroundColor: "rgba(255, 255, 255, 0.08)",
            borderRadius: 6,
            fontSize: 15,
            fontWeight: 600,
            color: "#cbd5e1",
          }}
        >
          Open Source (MIT / Apache-2.0)
        </div>
      </div>
    </AbsoluteFill>
  );
};
