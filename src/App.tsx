import '@fontsource/ibm-plex-sans';
import { Route, Routes, useLocation } from "react-router-dom";
import { useStytchMemberSession } from "@stytch/react/b2b";
import "./App.css";
import Settings from "./components/Settings";
import Members from "./components/Members";
import SSO from "./components/SSO";
import SCIM from "./components/SCIM";
import { Dashboard } from "./components/Dashboard";
import { SideNav } from "./components/SideNav";
import { LoginOrSignup } from "./components/LoginOrSignup";
import { Authenticate } from "./components/Authenticate";
import { ProtectedRoutes } from "./components/ProtectedRoutes";
import { Challenge } from "./components/Challenge";
import { Blocked } from "./components/Blocked";
import { JoinOrganization } from "./components/JoinOrganization";
import { Leaderboard } from './components/Leaderboard';

export const App = () => {
  const location = useLocation();
  const { session } = useStytchMemberSession();
  const showSidebar =
    session &&
    ["/dashboard", "/settings", "/members", "/sso", "/scim", "/leaderboard"].includes(location.pathname);

  return (
    <div className="app-container">
      {showSidebar && <SideNav />}
      <div className="centered-container">
        <Routes>
          <Route path="/" element={<JoinOrganization />} />
          <Route path="/cookie" element={<LoginOrSignup />} />
          <Route path="/cake" element={<LoginOrSignup />} />
          <Route path="/pie" element={<LoginOrSignup />} />
          <Route path="/authenticate" element={<Authenticate />} />
          <Route path="/challenge" element={<Challenge />} />
          <Route path="/blocked" element={<Blocked />} />
          <Route element={<ProtectedRoutes />}>
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/members" element={<Members />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="/sso" element={<SSO />} />
            <Route path="/scim" element={<SCIM />} />
            <Route path="/leaderboard" element={<Leaderboard limit={100} />} />
          </Route>
        </Routes>
      </div>
    </div>
  );
};
