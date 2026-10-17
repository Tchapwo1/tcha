# 🎬 AgentShield — 30-Second High-Energy Teaser Video

This project builds the official 30-second programmatic launch video for **AgentShield** using [Remotion](https://remotion.dev), strictly adhering to the [`remotion-video-craft`](file:///C:/Users/paris/.gemini/config/skills/remotion-video-craft/SKILL.md) and [`ui-animation-physics`](file:///C:/Users/paris/.gemini/config/skills/ui-animation-physics/SKILL.md) skill standards.

---

## ⏱️ Video Timeline (900 Frames @ 30 FPS = 30 Seconds)

| Scene | Time Range | Frames | Focus | Visual Engineering |
|---|---|---|---|---|
| **Scene 1: The Threat** | 0s – 6s | 0 – 180 | "AI Agents Have Full System Access With Zero Security Boundaries" | Kinetic typography with harmonic spring entrance (`damping: 14, stiffness: 120`), pulsing danger pill. |
| **Scene 2: The Exploit** | 6s – 14s | 180 – 420 | Live attack: indirect injection & SSRF payload stealing AWS metadata | Cyber terminal with macOS window chrome, syntax-highlighted code steps, pulsing crimson breach banner. |
| **Scene 3: The Shield** | 14s – 22s | 420 – 660 | AgentShield interception: SSRF Guard (0.8ms), XML Sanitizer, Merkle Ledger | Glowing emerald shield pop, 3-pillar staggered spring cards (`stiffness: 110`), HMAC signature challenge prompt. |
| **Scene 4: The Victory** | 22s – 30s | 660 – 900 | 50/50 Neutralized, 100% Resilience (Grade A+), `npx agentshield start` | Tabular figure metric scorecard, pulsating green CTA terminal box, GitHub link & open-source badge. |

---

## 🚀 How to Run

### 1. Install dependencies
```bash
npm install
```

### 2. Live Interactive Preview in Browser
Open the Remotion preview player to scrub frames and inspect animations:
```bash
npm start
```

### 3. Headless Production MP4 Render
Optimized specifically for laptops (i5 CPU / 8GB RAM) with concurrency limited to 1, ANGLE Direct3D hardware acceleration, and universal H.264 / YUV420p video encoding:
```bash
npm run build
```
Or execute the automated batch script:
```bash
.\render.bat
```

The final export will be saved to `out/agentshield_teaser.mp4`.
