import { useStytchMemberSession } from "@stytch/react/b2b";
import { useEffect, useRef, useState } from "react";
import { LoginOrSignup } from "./LoginOrSignup";
import { useNavigate } from 'react-router-dom';

export const Authenticate = (): JSX.Element => {
  const { session } = useStytchMemberSession();
  const alreadyLoggedInRef = useRef<boolean>();
  const [shouldRedirect, setShouldRedirect] = useState(false);
  const navigate = useNavigate();
  // Validate device fingerprint
  const validateDeviceFingerprint = async (): Promise<string> => {
    const telemetryId = await window.GetTelemetryID(
      import.meta.env.VITE_STYTCH_PUBLIC_TOKEN,
      "https://telemetry.stytch.com/submit",
    );
    // Add to backend call to validate telemetry id
    const response = await fetch("http://localhost:8787/api/validate", {
      method: "POST",
      body: JSON.stringify({ telemetryId }),
    });
    const data = await response.json();
    console.log(data.verdict.action);
    return data.verdict.action;
  };

  useEffect(() => {
    if (alreadyLoggedInRef.current === undefined) {
      alreadyLoggedInRef.current = !!session;

      if (session) {
        setShouldRedirect(true);
      }
    }
  }, [session]);

  if (shouldRedirect) {
    navigate("/dashboard", { replace: true });
  }

  validateDeviceFingerprint().then((verdict) => {
    if (verdict === "CHALLENGE") {
      //navigate("/challenge", { replace: true });
    } else if (verdict === "BLOCK") {
      navigate("/blocked", { replace: true });
    }
  });

  return <LoginOrSignup />;
};
