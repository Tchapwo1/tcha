import React from "react";
import { Composition } from "remotion";
import { TchaDemo } from "./Composition";

export const RemotionRoot: React.FC = () => {
  return (
    <Composition
      id="TchaDemo"
      component={TchaDemo}
      durationInFrames={900} // 30 seconds at 30fps
      fps={30}
      width={1920}
      height={1080}
    />
  );
};
