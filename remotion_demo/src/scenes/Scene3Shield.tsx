import React from "react";
import { AbsoluteFill, interpolate, spring, useCurrentFrame, useVideoConfig } from "remotion";
import { theme } from "../theme";

export const Scene3Shield: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  // Shield icon entrance
  const shieldEntrance = spring({
    frame,
    fps,
    config: { damping: 12, mass: 0.6, stiffness: 130 },
  });
  const shieldScale = interpolate(shieldEntrance, [0, 1], [0.6, 1]);
  const shieldOpacity = interpolate(shieldEntrance, [0, 1], [0, 1]);

  // Card 1: SSRF Guard
  const card1Entrance = spring({
    frame: frame - 25,
    fps,
    config: { damping: 14, mass: 0.7, stiffness: 110 },
  });
  const card1X = interpolate(card1Entrance, [0, 1], [-40, 0]);
  const card1Opacity = interpolate(card1Entrance, [0, 1], [0, 1]);

  // Card 2: Prompt Sanitizer
  const card2Entrance = spring({
    frame: frame - 55,
    fps,
    config: { damping: 14, mass: 0.7, stiffness: 110 },
  });
  const card2X = interpolate(card2Entrance, [0, 1], [-40, 0]);
  const card2Opacity = interpolate(card2Entrance, [0, 1], [0, 1]);

  // Card 3: Merkle Ledger
  const card3Entrance = spring({
    frame: frame - 85,
    fps,
    config: { damping: 14, mass: 0.7, stiffness: 110 },
  });
  const card3X = interpolate(card3Entrance, [0, 1], [-40, 0]);
  const card3Opacity = interpolate(card3Entrance, [0, 1], [0, 1]);

  // HITL Alert Banner
  const hitlEntrance = spring({
    frame: frame - 120,
    fps,
    config: { damping: 12, mass: 0.6, stiffness: 140 },
  });
  const hitlScale = interpolate(hitlEntrance, [0, 1], [0.95, 1]);
  const hitlOpacity = interpolate(hitlEntrance, [0, 1], [0, 1]);

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
        padding: 50,
      }}
    >
      {/* Background Emerald Ambient Glow */}
      <div
        style={{
          position: "absolute",
          width: 900,
          height: 900,
          borderRadius: "50%",
          background: "radial-gradient(circle, rgba(16, 185, 129, 0.14) 0%, transparent 65%)",
          filter: "blur(90px)",
        }}
      />

      {/* Top Header */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 18,
          marginBottom: 36,
          transform: `scale(${shieldScale})`,
          opacity: shieldOpacity,
        }}
      >
        <div
          style={{
            fontSize: 48,
            filter: `drop-shadow(0 0 20px ${theme.emeraldGlow})`,
          }}
        >
          🛡️
        </div>
        <div>
          <div style={{ fontSize: 44, fontWeight: 800, letterSpacing: "-0.02em" }}>
            Enter <span style={{ color: theme.emerald }}>Tcha Protection</span>
          </div>
          <div style={{ fontSize: 20, color: theme.textMuted }}>
            In-Line Zero-Trust Reverse Proxy for MCP & Autonomous Agents (Latency: &lt; 0.8ms)
          </div>
        </div>
      </div>

      {/* 3 Pillars Grid */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(3, 1fr)",
          gap: 24,
          width: 1400,
          marginBottom: 28,
        }}
      >
        {/* Pillar 1 */}
        <div
          style={{
            backgroundColor: theme.cardBg,
            border: "1px solid rgba(16, 185, 129, 0.3)",
            borderRadius: 14,
            padding: 24,
            transform: `translateX(${card1X}px)`,
            opacity: card1Opacity,
            boxShadow: "0 10px 30px rgba(0,0,0,0.5)",
          }}
        >
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 12 }}>
            <span style={{ fontWeight: 700, fontSize: 20, color: theme.emerald }}>SSRF GUARD</span>
            <span
              style={{
                fontSize: 13,
                backgroundColor: "rgba(16, 185, 129, 0.2)",
                color: "#6ee7b7",
                padding: "4px 8px",
                borderRadius: 4,
                fontWeight: 600,
              }}
            >
              0.78ms
            </span>
          </div>
          <p style={{ fontSize: 16, color: theme.textMuted, lineHeight: 1.5, marginBottom: 14 }}>
            Pre-flight DNS check blocks RFC-1918 &amp; 169.254.169.254 instance metadata immediately.
          </p>
          <div
            style={{
              fontFamily: theme.fontMono,
              fontSize: 14,
              color: "#34d399",
              backgroundColor: "rgba(16, 185, 129, 0.1)",
              padding: "8px 12px",
              borderRadius: 6,
            }}
          >
            ✓ BLOCKED: AWS Metadata
          </div>
        </div>

        {/* Pillar 2 */}
        <div
          style={{
            backgroundColor: theme.cardBg,
            border: "1px solid rgba(6, 182, 212, 0.3)",
            borderRadius: 14,
            padding: 24,
            transform: `translateX(${card2X}px)`,
            opacity: card2Opacity,
            boxShadow: "0 10px 30px rgba(0,0,0,0.5)",
          }}
        >
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 12 }}>
            <span style={{ fontWeight: 700, fontSize: 20, color: theme.cyan }}>PROMPT SANITIZER</span>
            <span
              style={{
                fontSize: 13,
                backgroundColor: "rgba(6, 182, 212, 0.2)",
                color: "#67e8f9",
                padding: "4px 8px",
                borderRadius: 4,
                fontWeight: 600,
              }}
            >
              Fenced
            </span>
          </div>
          <p style={{ fontSize: 16, color: theme.textMuted, lineHeight: 1.5, marginBottom: 14 }}>
            Encapsulates tool outputs inside strict XML delimiters to prevent prompt jailbreaks.
          </p>
          <div
            style={{
              fontFamily: theme.fontMono,
              fontSize: 14,
              color: "#38bdf8",
              backgroundColor: "rgba(6, 182, 212, 0.1)",
              padding: "8px 12px",
              borderRadius: 6,
            }}
          >
            ✓ &lt;untrusted_content&gt; safe
          </div>
        </div>

        {/* Pillar 3 */}
        <div
          style={{
            backgroundColor: theme.cardBg,
            border: "1px solid rgba(139, 92, 246, 0.3)",
            borderRadius: 14,
            padding: 24,
            transform: `translateX(${card3X}px)`,
            opacity: card3Opacity,
            boxShadow: "0 10px 30px rgba(0,0,0,0.5)",
          }}
        >
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 12 }}>
            <span style={{ fontWeight: 700, fontSize: 20, color: theme.violet }}>MERKLE LEDGER</span>
            <span
              style={{
                fontSize: 13,
                backgroundColor: "rgba(139, 92, 246, 0.2)",
                color: "#c4b5fd",
                padding: "4px 8px",
                borderRadius: 4,
                fontWeight: 600,
              }}
            >
              Tamper-Proof
            </span>
          </div>
          <p style={{ fontSize: 16, color: theme.textMuted, lineHeight: 1.5, marginBottom: 14 }}>
            Append-only SQLite WAL audit log with SHA-256 continuous cryptographic hash chaining.
          </p>
          <div
            style={{
              fontFamily: theme.fontMono,
              fontSize: 14,
              color: "#a78bfa",
              backgroundColor: "rgba(139, 92, 246, 0.1)",
              padding: "8px 12px",
              borderRadius: 6,
            }}
          >
            ✓ Block #4829 Verified
          </div>
        </div>
      </div>

      {/* Human-in-the-Loop Callout */}
      <div
        style={{
          width: 1400,
          backgroundColor: "rgba(234, 179, 8, 0.08)",
          border: "1px solid rgba(234, 179, 8, 0.4)",
          borderRadius: 12,
          padding: "16px 28px",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          transform: `scale(${hitlScale})`,
          opacity: hitlOpacity,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          <span style={{ fontSize: 28 }}>⚡</span>
          <div>
            <span style={{ fontWeight: 700, fontSize: 19, color: "#facc15" }}>
              Human-In-The-Loop Challenge Enforced:
            </span>{" "}
            <span style={{ fontFamily: theme.fontMono, fontSize: 17, color: theme.textMain }}>
              Tool &quot;execute_sql(DROP TABLE users)&quot; classified as Tier 3 (Destructive)
            </span>
          </div>
        </div>
        <div
          style={{
            fontFamily: theme.fontMono,
            fontSize: 15,
            backgroundColor: "rgba(234, 179, 8, 0.2)",
            color: "#fef08a",
            padding: "6px 14px",
            borderRadius: 6,
            fontWeight: 700,
          }}
        >
          HMAC-SHA256 SIGNATURE REQUIRED
        </div>
      </div>
    </AbsoluteFill>
  );
};
