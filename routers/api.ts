import env from '../config.ts';
import { jose, oak } from '../deps.ts';
import * as db from '../db.ts';
import * as types from '../types.ts';
import { randomStringWithEntropy } from '../util.ts';

const fileSizeMax = env.FILE_SIZE_MAX ?? 1024 * 1024 * 10;

type SubscriptionTicket = string;
type SubscriptionSet = string[];
const subscriptionTickets: Map<SubscriptionTicket, SubscriptionSet> = new Map();

const accessLogSubscriptions: Map<string, oak.ServerSentEventTarget[]> = new Map();
interface ClientConnectionMessage {
  shlId: string;
  recipient: string;
}
export const clientConnectionListener = (cxn: ClientConnectionMessage) => {
  (accessLogSubscriptions.get(cxn.shlId) || []).forEach((t, _i) => {
    t.dispatchEvent(new oak.ServerSentEvent('connection', cxn));
  });
};

interface ManifestAccessTicket {
  shlId: string;
}
const manifestAccessTickets: Map<string, ManifestAccessTicket> = new Map();

export const router = new oak.Router();

/**
 * Open endpoints for SHL and content access
 */
/** Request SHL manifest */
router.post('/shl/:shlId', async (context) => {
  const config: types.HealthLinkManifestRequest = await context.request.body({ type: 'json' }).value;
  const embeddedLengthMax = Math.min(env.EMBEDDED_LENGTH_MAX, config.embeddedLengthMax !== undefined ? config.embeddedLengthMax : Infinity);
  if (!config.recipient) {
    context.throw(400, "Missing recipient in request body");
    return;
  }

  let shl: types.HealthLink | undefined = db.DbLinks.getShlInternal(context.params.shlId);
  
  if (shl === undefined) {
    context.throw(404, "SHL does not exist or has been deactivated.");
    return;
  }

  if (!shl?.active) {
    context.throw(404, "SHL does not exist or has been deactivated.");
    return;
  }
  if (shl.config.exp && new Date(shl.config.exp * 1000).getTime() < new Date().getTime()) {
    context.throw(404, "SHL is expired");
    return;
  }
  if (shl.config.passcode && !("passcode" in config)) {
    context.throw(401, "Passcode required", {remainingAttempts: shl.passcodeFailuresRemaining});
    return;
  }
  if (shl.config.passcode && shl.config.passcode !== config.passcode) {
    db.DbLinks.recordPasscodeFailure(shl.id);
    context.throw(401, "Incorrect passcode", {remainingAttempts: shl.passcodeFailuresRemaining - 1});
    return;
  }

  const ticket = randomStringWithEntropy(32);
  manifestAccessTickets.set(ticket, {
    shlId: shl.id,
  });
  setTimeout(() => {
    manifestAccessTickets.delete(ticket);
  }, 60000);
  db.DbLinks.recordAccess(shl.id, config.recipient);

  context.response.headers.set('expires', new Date().toUTCString());
  context.response.headers.set('content-type', 'application/json');
  context.response.body = {
    files: db.DbLinks.getManifestFiles(shl.id, embeddedLengthMax)
      .map((f, _i) => ({
        contentType: f.contentType,
        embedded: f.content?.length ? new TextDecoder().decode(f.content) : undefined,
        location: `${env.PUBLIC_URL}/api/shl/${shl?.id}/file/${f.hash}?ticket=${ticket}`,
      }))
      .concat(
        db.DbLinks.getManifestEndpoints(shl.id).map((e) => ({
          contentType: 'application/smart-api-access',
          embedded: undefined,
          location: `${env.PUBLIC_URL}/api/shl/${shl?.id}/endpoint/${e.id}?ticket=${ticket}`,
        })),
      ),
  };
  return;
});
/** Request SHL file from manifest */
router.get('/shl/:shlId/file/:fileIndex', (context) => {
  const ticket = manifestAccessTickets.get(context.request.url.searchParams.get('ticket')!);
  if (!ticket) {
    console.log('Cannot request SHL without a valid ticket');
    context.throw(401, "Unauthorized");
    return;
  }

  if (ticket.shlId !== context.params.shlId) {
    console.log('Ticket is not valid for ' + context.params.shlId);
    context.throw(401, "Unauthorized");
    return;
  }

  const file = db.DbLinks.getFile(context.params.shlId, context.params.fileIndex);
  context.response.headers.set('content-type', 'application/jose');
  context.response.body = file.content;
  return;
});
/** Request SHL endpoint from manifest */
router.get('/shl/:shlId/endpoint/:endpointId', async (context) => {
  const ticket = manifestAccessTickets.get(context.request.url.searchParams.get('ticket')!);
  if (!ticket) {
    console.log('Cannot request SHL without a valid ticket');
    context.throw(401, "Unauthorized");
    return;
  }

  if (ticket.shlId !== context.params.shlId) {
    console.log('Ticket is not valid for ' + context.params.shlId);
    context.throw(401, "Unauthorized");
    return;
  }

  const endpoint = await db.DbLinks.getEndpoint(context.params.shlId, context.params.endpointId);
  if (!endpoint) {
    context.throw(404, "Endpoint not found.");
    return;
  }
  context.response.headers.set('content-type', 'application/jose');
  const payload = JSON.stringify({
    aud: endpoint.endpointUrl,
    ...endpoint.accessTokenResponse,
  });
  const encrypted = await new jose.CompactEncrypt(new TextEncoder().encode(payload))
    .setProtectedHeader({
      alg: 'dir',
      enc: 'A256GCM',
    })
    .encrypt(jose.base64url.decode(endpoint.config.key));
  context.response.body = encrypted;
  return;
});
/** Check if SHL is active */
router.get('/shl/:shlId/active', (context) => {
  const shl = db.DbLinks.getShlInternal(context.params.shlId);
  if (!shl) {
    context.throw(404, "SHL does not exist or has been deactivated.");
    return;
  }
  const isActive = (shl && shl.active);
  console.log(context.params.shlId + " active: " + isActive);
  context.response.body = isActive;
  context.response.headers.set('content-type', 'application/json');
  return;
});
/** [Deprecated] Demo iis endpoint for HIMSS 2024 */
router.post('/iis', async(context) => {
  const content = await context.request.body({ type: 'json' }).value;
  const response = await fetch('http://35.160.125.146:8039/fhir/Patient/', {
    method: 'POST',
    headers: content.headers,
    body: JSON.stringify(content)
  });
  if (!response.ok) {
    throw new Error('Unable to fetch IIS immunization data');
  }
  const body = await response.json();
  context.response.body = body;
  return;
});

/**
 * Middleware for JWT validation in front of below routes if necessary
 */
router.use(authMiddleware);

/**
 * Endpoints behind JWT validation middleware when enabled
*/
/**
 * TODO: Change to GET after committing to jwt auth
 * Current body required: { userId: string }
*/
/** Simple auth check endpoint to open auth middleware check to external services */
router.post('/authcheck', async (context: oak.Context) => {
  const userId = context.state.auth.sub;
  console.log("Authcheck: " + userId);
  if (!userId) {
    context.throw(401, "Unauthorized");
    return;
  }
  context.response.headers.set('Content-Type', 'application/json');
  context.response.status = 200;
  context.response.body = { authorized: true };
  return;
});
/** Get SHLs for user */
router.post('/user', async (context: oak.Context) => {
  const shls = db.DbLinks.getUserShls(context.state.auth.sub)!;
  if (!shls) {
    console.log(`No SHLinks for user ` + context.state.auth.sub);
    context.response.body = [];
    return;
  }
  context.response.body = shls;
  return;
});
/** Create SHL */
router.post('/shl', async (context) => {
  const config: types.HealthLinkConfig = await context.request.body({ type: 'json' }).value;
  const newLink = db.DbLinks.create(config);
  console.log("Created link " + newLink.id);
  const encodedPayload: string = jose.base64url.encode(JSON.stringify(prepareMinimalShlForReturn(newLink)));
  const shlinkBare = `shlink:/${encodedPayload}`;
  context.response.headers.set('content-type', 'text/plain; charset=utf-8');
  context.response.body = shlinkBare;
  return;
});
/** Update SHL */
router.put('/shl/:shlId', async (context) => {
  const userId = context.state.auth.sub;
  const config: types.HealthLinkConfig = await context.request.body({ type: 'json' }).value;
  if (!db.DbLinks.linkExists(context.params.shlId)) {
    context.throw(404, "SHL does not exist or has been deactivated.");
    return;
  }
  const shl = db.DbLinks.getUserShl(context.params.shlId, userId)!;
  if (!shl) {
    context.throw(401, "Unauthorized");
    return;
  }
  shl.config.exp = config.exp ?? shl.config.exp;
  shl.config.passcode = config.passcode ?? shl.config.passcode;
  shl.label = config.label ?? shl.label;
  const updated = db.DbLinks.updateConfig(shl);
  const updatedShl = db.DbLinks.getUserShl(context.params.shlId, userId)!;
  context.response.headers.set('content-type', 'application/json');
  context.response.body = prepareShlForReturn(updatedShl);
  return;
});
/** Deactivate SHL */
router.delete('/shl/:shlId', async (context) => {
  const userId = context.state.auth.sub;
  if (!db.DbLinks.linkExists(context.params.shlId)) {
    context.throw(404, "SHL does not exist or has been deactivated.");
    return;
  }
  try {
    const shl = db.DbLinks.getUserShlInternal(context.params.shlId, userId)!;
    if (!shl) {
      context.throw(401, "Unauthorized");
      return;
    }
    const deactivated = db.DbLinks.deactivate(shl);
    if (!deactivated) {
      context.throw(500, "Failed to delete SHL");
      return;
    }
    const updatedShlList = db.DbLinks.getUserShls(userId)!;
    context.response.headers.set('content-type', 'application/json');
    context.response.body = updatedShlList;
  } catch {
    context.throw(404, "SHL does not exist or has been deactivated.");
  }
  return;
});
/** Reactivate SHL */
router.put('/shl/:shlId/reactivate', async (context) => {
  const userId = context.state.auth.sub;
  const shl = db.DbLinks.getUserShlInternal(context.params.shlId, userId)!;
  if (!shl) {
    context.throw(401, "Unauthorized");
    return;
  }
  const success = db.DbLinks.reactivate(shl)!;
  console.log("Reactivated " + context.params.shlId + ": " + success);
  context.response.headers.set('content-type', 'application/json');
  context.response.body = success;
  return;
});
/** Add file to SHL */
router.post('/shl/:shlId/file', async (context) => {
  const userId = context.state.auth.sub;
  const newFileBody = await context.request.body({
    type: 'bytes',
    limit: fileSizeMax
  });

  if (!db.DbLinks.linkExists(context.params.shlId)) {
    context.throw(404, "SHL does not exist or has been deactivated.");
    return;
  }
  const shl = db.DbLinks.getUserShlInternal(context.params.shlId, userId)!;
  if (!shl) {
    context.throw(401, "Unauthorized");
    return;
  }

  let contentLength = context.request.headers.get('content-length');
  if (contentLength === null) {
    context.throw(400, "Missing content length");
    return;
  }
  if (Number(contentLength) > fileSizeMax) {
    context.throw(413, "Size limit exceeded");
    return;
  }

  const newFile = {
    contentType: context.request.headers.get('content-type')!,
    content: await newFileBody.value,
  };

  const added = await db.DbLinks.addFile(shl.id, newFile);
  const updatedShl = db.DbLinks.getUserShl(shl.id, userId)!;
  context.response.headers.set('content-type', 'application/json');
  context.response.body = prepareShlForReturn(updatedShl);
  return;
});
/** Delete file from SHL */
router.delete('/shl/:shlId/file', async (context) => {
  const userId = context.state.auth.sub;
  const currentFileHash = await context.request.body({type: 'text'}).value;
  if (!db.DbLinks.linkExists(context.params.shlId)) {
    context.throw(404, "SHL does not exist or has been deactivated.");
    return;
  }
  const shl = db.DbLinks.getUserShlInternal(context.params.shlId, userId)!;
  if (!shl) {
    context.throw(401, "Unauthorized");
    return;
  }
  
  const deleted = db.DbLinks.deleteFile(shl.id, currentFileHash);
  if (!db.DbLinks.linkExists(context.params.shlId)) {
    context.throw(500, "Failed to delete file");
    return;
  }
  const updatedShl = db.DbLinks.getUserShl(shl.id, userId)!;
  context.response.headers.set('content-type', 'application/json');
  context.response.body = prepareShlForReturn(updatedShl);
  return;
});
/** Add endpoint to SHL */
router.post('/shl/:shlId/endpoint', async (context) => {
  const userId = context.state.auth.sub;
  const config: types.HealthLinkEndpoint = await context.request.body({ type: 'json' }).value;

  if (!db.DbLinks.linkExists(context.params.shlId)) {
    context.throw(404, "SHL does not exist or has been deactivated.");
    return;
  }
  const shl = db.DbLinks.getUserShlInternal(context.params.shlId, userId)!;
  if (!shl) {
    context.throw(401, "Unauthorized");
    return;
  }

  const added = await db.DbLinks.addEndpoint(shl.id, config);
  console.log("Added", added)
  const updatedShl = db.DbLinks.getUserShl(context.params.shlId, userId)!;
  context.response.headers.set('content-type', 'application/json');
  context.response.body = prepareShlForReturn(updatedShl);
  return;
});
/** Subscribe to SHLs related to a management token */
router.post('/subscribe', async (context) => {
  const userId = context.state.auth.sub;
  const shlSet: { shlId: string; managementToken: string }[] = await context.request.body({ type: 'json' }).value;
  const managedLinks = shlSet.map((req) => db.DbLinks.getManagedShl(req.shlId, req.managementToken));

  const ticket = randomStringWithEntropy(32, 'subscription-ticket-');
  subscriptionTickets.set(
    ticket,
    managedLinks.map((l) => l?.id ?? '' ),
  );
  setTimeout(() => {
    subscriptionTickets.delete(ticket);
  }, 10000);
  context.response.body = { subscribe: `${env.PUBLIC_URL}/api/subscribe/${ticket}` };
  context.response.status = 200;
  return;
});
/** Get subscribed SHLs for a ticket */
router.get('/subscribe/:ticket', (context) => {
  const validForSet = subscriptionTickets.get(context.params.ticket);
  if (!validForSet) {
    throw 'Invalid ticket for SSE subscription';
  }

  const target = context.sendEvents();
  for (const shl of validForSet) {
    if (!accessLogSubscriptions.has(shl)) {
      accessLogSubscriptions.set(shl, []);
    }
    accessLogSubscriptions.get(shl)!.push(target);
    target.dispatchEvent(new oak.ServerSentEvent('status', db.DbLinks.getShlInternal(shl)));
  }

  const keepaliveInterval = setInterval(() => {
    target.dispatchEvent(new oak.ServerSentEvent('keepalive', JSON.stringify({ shlCount: validForSet.length })));
  }, 15000);

  target.addEventListener('close', () => {
    clearInterval(keepaliveInterval);
    for (const shl of validForSet) {
      const idx = accessLogSubscriptions.get(shl)!.indexOf(target);
      accessLogSubscriptions.get(shl)!.splice(idx, 1);
    }
  });
  context.response.status = 200;
  return;
});

/*
router.post('/register', (context) => {
})
/*
  files: DbLinks.fileNames(client.shlink).map(
          (f, _i) => ({contentType: f.contentType, location: `${env.PUBLIC_URL}/api/shl/${client.shlink}/file/${f}`}),
  ),

*/

/** JWT validation middleware */
async function authMiddleware(context: oak.Context, next: () => Promise<unknown>) {

  // TODO: temp - remove in favor of jwt
  // Adapter to handle user id in body
  try {
    const content = await context.request.body({ type: 'json' }).value;
    if (content.userId) {
      console.log("Using user id from body: " + content.userId);
      context.state.auth = { sub: content.userId };
      return next();
    }
    console.log("No user id in body");
    throw Error("No body");
  } catch (e) {
    console.log("No body, skipping userId check");
  }
  // temp

  const token = context.request.headers.get('Authorization');
  if (!token) {
    context.throw(400, "Missing token in request header");
    return;
  }

  const tokenValue = token.split(' ')[1];
  if (!tokenValue) {
    context.throw(400, "Missing token in request header");
    return;
  }

  // TODO: temp - remove in favor of jwt
  // Adapter to handle management token auth header
  if (db.DbLinks.managementTokenExists(tokenValue)) {
    console.log("Trying management token: " + tokenValue);
    let mtUser = db.DbLinks.getManagementTokenUserInternal(tokenValue);
    console.log("MT user: " + JSON.stringify(mtUser));
    if (mtUser) {
      context.state.auth = { sub: db.DbLinks.getManagementTokenUserInternal(tokenValue) };
      console.log("User: " + context.state.auth.sub);
      return next();
    }
  }
  // temp
  
  if (!env.JWKS_URL) {
    context.throw(401, "Invalid token");
    return;
  }

  const jwks = await jose.createRemoteJWKSet(new URL(env.JWKS_URL));

  try {
    const verifiedDecodedToken = await jose.jwtVerify(tokenValue, jwks, {
      algorithms: ['RS256'],
      audience: ['account'],
    });
    context.state.auth = verifiedDecodedToken.payload;
    
    return next();
  
  } catch (error) {
    console.log(JSON.stringify(error));
    context.throw(401, "Invalid token");
    return;
  }
}

function prepareMinimalShlForReturn(shl: types.HealthLinkFull) {
  let flat = {
    ...shl,
    ...shl.config,
  };
  const keys = [
    "id",
    "url",
    "key",
    "exp",
    "flag",
    "label",
    "v",
  ];
  const subset: types.SHLDecoded = Object.fromEntries(
    Object.entries(flat).filter(([key]) => keys.includes(key))
  ) as unknown as types.SHLDecoded;
  return subset;
}

function prepareShlForReturn(shl: types.HealthLinkFull) {
  let flat: types.HealthLinkFullReturn = {
    ...shl,
    ...shl.config,
  };
  delete flat.config;
  return flat;
}

export const shlApiRouter = router;
