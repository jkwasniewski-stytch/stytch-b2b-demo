import { AdminPortalB2BProducts } from '@stytch/react/b2b/adminPortal'
import { AuthFlowType, B2BProducts, B2BOAuthProviders } from "@stytch/vanilla-js";

type Role = {
  role_id: string;
  description: string;
}

export const adminPortalConfig = {
  allowedAuthMethods: [
    AdminPortalB2BProducts.oauthGoogle
  ],
  getRoleDescription: (role: Role) => {
    return role.description;
  },
  getRoleDisplayName: (role: Role) => {
    return role.role_id
  }
}

export const discoveryConfig = {
  products: [B2BProducts.oauth],
  sessionOptions: { sessionDurationMinutes: 60 },
  oauthOptions: {
    providers: [{type: B2BOAuthProviders.Google}]
  },
  authFlowType: AuthFlowType.Organization
};

export const adminPortalStyles = {
  fontFamily: 'IBM Plex Sans',
}

export const discoveryStyles = {
  fontFamily: 'IBM Plex Sans',
  container: {
    width: '500px',
  },
}