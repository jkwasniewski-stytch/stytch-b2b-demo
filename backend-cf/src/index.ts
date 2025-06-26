import stytch from 'stytch';

export interface Env {
  STYTCH_PROJECT_ID: string;
  STYTCH_SECRET: string;
  APP_DOMAIN: string;
}

const ROLES = [{
  name: 'newbie',
  value: '10',
}, {
  name: 'novice',
  value: '20',
}, {
  name: 'head baker',
  value: '30',
}, {
  name: 'baker overlord',
  value: '40'
}]

// We are being hacky.. please don't judge me
function monkeyPatchStytchClientSettings(client: any) {
  client.fetchConfig.cache = undefined;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const DEFAULT_HEADERS = {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': env.APP_DOMAIN,
      'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization',
    };

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: DEFAULT_HEADERS,
      });
    }

    const stytchClient = new stytch.B2BClient({
      project_id: (env.STYTCH_PROJECT_ID as string) || '',
      secret: (env.STYTCH_SECRET as string) || '',
    });
    monkeyPatchStytchClientSettings(stytchClient);


    if (url.pathname === '/api/leaderboard' && request.method === 'GET') {
      const limit = parseInt(url.searchParams.get('limit') || '5');
      try {
        const orgs = await stytchClient.organizations.search({
          limit: 10,
        })
        const members = await stytchClient.organizations.members.search({
          limit: 200,
          organization_ids: orgs.organizations.map((org) => org.organization_id),
        });
        const leaderboard = members.members.map((member) => ({
          name: `${member.name.split(' ')[0]} ${member.name.split(' ')[1][0]}.`,
          baked: member.trusted_metadata?.baked,
          organization: orgs.organizations.find((org) => org.organization_id === member.organization_id)?.organization_name,
        })).sort((a, b) => parseInt(b.baked || '0') - parseInt(a.baked || '0'));
        const filteredLeaderboard = leaderboard.filter((member) => member.baked !== undefined).slice(0, limit);
        return new Response(JSON.stringify({ leaderboard: filteredLeaderboard }), {
          headers: DEFAULT_HEADERS,
        });
      } catch (err: any) {
        return new Response(JSON.stringify({ error: err.message }), {
          status: 401,
          headers: DEFAULT_HEADERS,
        });
      }
    }

    // Validate device fingerprint using telemetry id
    if (url.pathname === '/api/validate' && request.method === 'POST') {
      try {
        const body = await request.json();
        const { telemetryId } = body;
        const response = await stytchClient.fraud.fingerprint.lookup({
          telemetry_id: telemetryId,
        });
        return new Response(JSON.stringify({ verdict: response.verdict }), {
          headers: DEFAULT_HEADERS,
        });
      } catch (err: any) {
        return new Response(JSON.stringify({ error: err.message }), {
          status: 401,
          headers: DEFAULT_HEADERS,
        });
      }
    }

    const sessionToken = request.headers.get('Authorization')?.split(' ')[1];
    if (!sessionToken) return new Response('Unauthorized', { status: 401, headers: DEFAULT_HEADERS });
    const session = await stytchClient.sessions.authenticate({ session_token: sessionToken})
    if (!session) return new Response('Unauthorized', { status: 401, headers: DEFAULT_HEADERS });

    // Validate device fingerprint using telemetry id
    if (url.pathname === '/api/feed' && request.method === 'POST') {
      try {
        const body = await request.json();
        const { count } = body;
        const response = await stytchClient.organizations.members.update({
          organization_id: session.organization.organization_id,
          member_id: session.member.member_id,
          trusted_metadata: {
            baked: (count + (session.member.trusted_metadata?.baked || 0)),
          },
        });
        return new Response(JSON.stringify({ response }), {
          headers: DEFAULT_HEADERS,
        });
      } catch (err: any) {
        return new Response(JSON.stringify({ error: err.message }), {
          status: 401,
          headers: DEFAULT_HEADERS,
        });
      }
    }

    // Validate device fingerprint using telemetry id
    if (url.pathname === '/api/promote' && request.method === 'GET') {
      try {
        const roles = ROLES.filter((role) => role.value <= session.member.trusted_metadata?.baked)
        await stytchClient.organizations.members.update({
          organization_id: session.organization.organization_id,
          member_id: session.member.member_id,
          roles: roles.map((role) => role.name),
        });
        return new Response(JSON.stringify({ role: roles.slice(-1)[0].name || 'nobody' }), {
          headers: DEFAULT_HEADERS,
        });
      } catch (err: any) {
        return new Response(JSON.stringify({ error: err.message }), {
          status: 401,
          headers: DEFAULT_HEADERS,
        });
      }
    }

    return new Response('Not found', { status: 404, headers: DEFAULT_HEADERS });
  },
};
