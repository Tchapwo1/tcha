import React from "react";
import { AbsoluteFill, Sequence } from "remotion";
import { Scene1Hook } from "./scenes/Scene1Hook";
import { Scene2Exploit } from "./scenes/Scene2Exploit";
import { Scene3Shield } from "./scenes/Scene3Shield";
import { Scene4Victory } from "./scenes/Scene4Victory";

export const TchaDemo: React.FC = () => {
  return (
    <AbsoluteFill style={{ backgroundColor: "#05070c" }}>
      {/* Scene 1: The Vulnerability & Threat Hook (0s - 6s, 180 frames) */}
      <Sequence from={0} durationInFrames={180}>
        <Scene1Hook />
      </Sequence>

      {/* Scene 2: The Exploit & Unshielded Breach (6s - 14s, 240 frames) */}
      <Sequence from={180} durationInFrames={240}>
        <Scene2Exploit />
      </Sequence>

      {/* Scene 3: AgentShield Interception & Defense (14s - 22s, 240 frames) */}
      <Sequence from={420} durationInFrames={240}>
        <Scene3Shield />
      </Sequence>

      {/* Scene 4: 100% Resilience Benchmark & CTA (22s - 30s, 240 frames) */}
      <Sequence from={660} durationInFrames={240}>
        <Scene4Victory />
      </Sequence>
    </AbsoluteFill>
  );
};
