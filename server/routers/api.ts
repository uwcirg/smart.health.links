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
    context.response.status = 400;
    context.response.body = { message: "Missing recipient in request body" };
    context.response.headers.set('Content-Type', 'application/json');
    return context.response;
  }

  let shl: types.HealthLink;
  try {
    shl = db.DbLinks.getShlInternal(context.params.shlId);
  } catch {
    context.response.status = 404;
    context.response.body = { message: "SHL does not exist or has been deactivated."};
    context.response.headers.set('Content-Type', 'application/json');
    return context.response;
  }

  if (!shl?.active) {
    context.response.status = 404;
    context.response.body = { message: "SHL does not exist or has been deactivated." };
    context.response.headers.set('Content-Type', 'application/json');
    return context.response;
  }
  if (shl.config.exp && new Date(shl.config.exp * 1000).getTime() < new Date().getTime()) {
    context.response.status = 403;
    context.response.body = { message: "SHL is expired" };
    context.response.headers.set('Content-Type', 'application/json');
    return context.response;
  }
  if (shl.config.passcode && !("passcode" in config)) {
    context.response.status = 401;
    context.response.body = {
      message: "Passcode required",
      remainingAttempts: shl.passcodeFailuresRemaining
    }
    context.response.headers.set('Content-Type', 'application/json');
    return context.response;
  }
  if (shl.config.passcode && shl.config.passcode !== config.passcode) {
    db.DbLinks.recordPasscodeFailure(shl.id);
    context.response.status = 401;
    context.response.body = {
      message: "Incorrect password",
      remainingAttempts: shl.passcodeFailuresRemaining - 1
    };
    context.response.headers.set('Content-Type', 'application/json');
    return context.response;
  }

  const ticket = randomStringWithEntropy(32);
  manifestAccessTickets.set(ticket, {
    shlId: shl.id,
  });
  setTimeout(() => {
    manifestAccessTickets.delete(ticket);
  }, 60000);
  db.DbLinks.recordAccess(shl.id, config.recipient);

  context.response.headers.set('Expires', new Date().toUTCString());
  context.response.headers.set('Content-Type', 'application/json');
  context.response.body ={
    files: db.DbLinks.getManifestFiles(shl.id, embeddedLengthMax)
      .map((f, _i) => ({
        contentType: f.contentType,
        embedded: f.content?.length ? new TextDecoder().decode(f.content) : undefined,
        location: `${env.PUBLIC_URL}/api/shl/${shl.id}/file/${f.hash}?ticket=${ticket}`,
      }))
      .concat(
        db.DbLinks.getManifestEndpoints(shl.id).map((e) => ({
          contentType: 'application/smart-api-access',
          embedded: undefined,
          location: `${env.PUBLIC_URL}/api/shl/${shl.id}/endpoint/${e.id}?ticket=${ticket}`,
        })),
      ),
  };
  return context.response;
});
/** Request SHL file from manifest */
router.get('/shl/:shlId/file/:fileIndex', (context) => {
  const ticket = manifestAccessTickets.get(context.request.url.searchParams.get('ticket')!);
  if (!ticket) {
    console.log('Cannot request SHL without a valid ticket');
    context.response.status = 401;
    context.response.body = { message: "Unauthorized" }
    context.response.headers.set('Content-Type', 'application/json');
    return context.response;
  }

  if (ticket.shlId !== context.params.shlId) {
    console.log('Ticket is not valid for ' + context.params.shlId);
    context.response.status = 401;
    context.response.body = { message: "Unauthorized" }
    context.response.headers.set('Content-Type', 'application/json');
    return context.response;
  }

  const file = db.DbLinks.getFile(context.params.shlId, context.params.fileIndex);
  context.response.headers.set('Content-Type', 'application/jose');
  context.response.body = file.content;
  return context.response;
});
/** Request SHL endpoint from manifest */
router.get('/shl/:shlId/endpoint/:endpointId', async (context) => {
  const ticket = manifestAccessTickets.get(context.request.url.searchParams.get('ticket')!);
  if (!ticket) {
    console.log('Cannot request SHL without a valid ticket');
    context.response.status = 401;
    context.response.body = { message: "Unauthorized" }
    context.response.headers.set('Content-Type', 'application/json');
    return context.response;
  }

  if (ticket.shlId !== context.params.shlId) {
    console.log('Ticket is not valid for ' + context.params.shlId);
    context.response.status = 401;
    context.response.body = { message: "Unauthorized" };
    context.response.headers.set('Content-Type', 'application/json');
    return context.response;
  }

  const endpoint = await db.DbLinks.getEndpoint(context.params.shlId, context.params.endpointId);
  context.response.headers.set('Content-Type', 'application/jose');
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
  return context.response;
});
/** Check if SHL is active */
router.get('/shl/:shlId/active', (context) => {
  const shl = db.DbLinks.getShlInternal(context.params.shlId);
  if (!shl) {
    context.response.status = 404;
    context.response.body = { message: `Deleted` };
    context.response.headers.set('Content-Type', 'application/json');
    return context.response;
  }
  const isActive = (shl && shl.active);
  console.log(context.params.shlId + " active: " + isActive);
  context.response.body = isActive;
  context.response.headers.set('Content-Type', 'application/json');
  return context.response;
});
/** [Deprecated] Demo iis endpoint for HIMSS 2024 */
router.post('/iis', async(context) => {
  const content = await context.request.body({ type: 'json' }).value;
  const response = await fetch('http://35.160.125.146:8039/fhir/Patient/', {
    method: 'POST',
    headers: content.headers,
    body: JSON.stringify(content)
  });
  if (response.ok) {
    const body = await response.json();
    context.response.body = body;
    return context.response;
  } else {
    throw new Error('Unable to fetch IIS immunization data');
  };
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
/** Get SHLs for user */
router.post('/user', async (context: oak.Context) => {
  const shls = db.DbLinks.getUserShls(context.state.auth.sub)!;
  if (!shls) {
    console.log(`No SHLinks for user ` + context.state.auth.sub);
    context.response.body = [];
    return context.response;
  }
  context.response.body = shls;
  return context.response;
});
/** Create SHL */
router.post('/shl', async (context) => {
  const config: types.HealthLinkConfig = await context.request.body({ type: 'json' }).value;
  console.log("Config posted:" + JSON.stringify(config));
  const newLink = db.DbLinks.create(config);
  console.log("Created link " + newLink.id);
  const encodedPayload: string = jose.base64url.encode(JSON.stringify(prepareMinimalShlForReturn(newLink)));
  const shlinkBare = `shlink:/${encodedPayload}`;
  context.response.headers.set('Content-Type', 'application/text/plain');
  context.response.body = shlinkBare;
  return context.response;
});
/** Update SHL */
router.put('/shl/:shlId', async (context) => {
  const userId = context.state.auth.sub;
  const config: types.HealthLinkConfig = await context.request.body({ type: 'json' }).value;
  if (!db.DbLinks.linkExists(context.params.shlId)) {
    context.response.status = 404;
    context.response.body = { message: "SHL does not exist or has been deactivated." };
    context.response.headers.set('Content-Type', 'application/json');
    return context.response;
  }
  const shl = db.DbLinks.getUserShl(context.params.shlId, userId)!;
  if (!shl) {
    context.response.status = 401;
    context.response.body = { message: `Unauthorized` };
    context.response.headers.set('Content-Type', 'application/json');
    return context.response;
  }
  shl.config.exp = config.exp ?? shl.config.exp;
  shl.config.passcode = config.passcode ?? shl.config.passcode;
  shl.label = config.label ?? shl.label;
  const updated = db.DbLinks.updateConfig(shl);
  const updatedShl = db.DbLinks.getUserShl(context.params.shlId, userId)!;
  context.response.headers.set('Content-Type', 'application/json');
  context.response.body = prepareShlForReturn(updatedShl);
  return context.response;
});
/** Deactivate SHL */
router.delete('/shl/:shlId', async (context) => {
  const userId = context.state.auth.sub;
  if (!db.DbLinks.linkExists(context.params.shlId)) {
    context.response.status = 404;
    context.response.body = { message: "SHL does not exist or has been deactivated." };
    context.response.headers.set('Content-Type', 'application/json');
    return context.response;
  }
  try {
    const shl = db.DbLinks.getUserShlInternal(context.params.shlId, userId)!;
    if (!shl) {
      context.response.status = 401;
      context.response.body = { message: `Unauthorized` };
      context.response.headers.set('Content-Type', 'application/json');
      return context.response;
    }
    const deactivated = db.DbLinks.deactivate(shl);
    if (!deactivated) {
      context.response.status = 500;
      context.response.body = { message: "Failed to delete SHL" };
      context.response.headers.set('Content-Type', 'application/json');
      return context.response;
    }
    const updatedShlList = db.DbLinks.getUserShls(userId)!;
    context.response.headers.set('Content-Type', 'application/json');
    context.response.body = updatedShlList;
    return context.response;
  } catch {
    context.response.status = 404;
    context.response.body = { message: "SHL does not exist" };
    context.response.headers.set('Content-Type', 'application/json');
    return context.response;
  }
});
/** Reactivate SHL */
router.put('/shl/:shlId/reactivate', async (context) => {
  const userId = context.state.auth.sub;
  const shl = db.DbLinks.getUserShlInternal(context.params.shlId, userId)!;
  if (!shl) {
    context.response.status = 401;
    context.response.body = { message: `Unauthorized` };
    context.response.headers.set('Content-Type', 'application/json');
    return context.response;
  }
  const success = db.DbLinks.reactivate(shl)!;
  console.log("Reactivated " + context.params.shlId + ": " + success);
  context.response.headers.set('Content-Type', 'application/json');
  context.response.body = success;
  return context.response;
});
/** Add file to SHL */
router.post('/shl/:shlId/file', async (context) => {
  const userId = context.state.auth.sub;
  const newFileBody = await context.request.body({
    type: 'bytes',
    limit: fileSizeMax
  });

  if (!db.DbLinks.linkExists(context.params.shlId)) {
    context.response.status = 404;
    context.response.body = { message: "SHL does not exist or has been deactivated." };
    context.response.headers.set('Content-Type', 'application/json');
    return context.response;
  }
  const shl = db.DbLinks.getUserShlInternal(context.params.shlId, userId)!;
  if (!shl) {
    context.response.status = 401;
    context.response.body = { message: `Unauthorized` };
    context.response.headers.set('Content-Type', 'application/json');
    return context.response;
  }

  let contentLength = context.request.headers.get('content-length');
  if (contentLength === null) {
    context.response.status = 400;
    context.response.body = { message: `Missing content length` };
    context.response.headers.set('Content-Type', 'application/json');
    return context.response;
  }
  if (Number(contentLength) > fileSizeMax) {
    context.response.status = 413;
    context.response.body = { message: `Size limit exceeded` };
    context.response.headers.set('Content-Type', 'application/json');
    return context.response;
  }

  const newFile = {
    contentType: context.request.headers.get('Content-Type')!,
    content: await newFileBody.value,
  };

  const added = await db.DbLinks.addFile(shl.id, newFile);
  const updatedShl = db.DbLinks.getUserShl(shl.id, userId)!;
  context.response.headers.set('Content-Type', 'application/json');
  context.response.body = prepareShlForReturn(updatedShl);
  return context.response;
});
/** Delete file from SHL */
router.delete('/shl/:shlId/file', async (context) => {
  const userId = context.state.auth.sub;
  const currentFileHash = await context.request.body({type: 'bytes'});
  if (!db.DbLinks.linkExists(context.params.shlId)) {
    context.response.status = 404;
    context.response.body = { message: "SHL does not exist or has been deactivated." };
    context.response.headers.set('Content-Type', 'application/json');
    return context.response;
  }
  const shl = db.DbLinks.getUserShlInternal(context.params.shlId, userId)!;
  if (!shl) {
    context.response.status = 401;
    context.response.body = { message: `Unauthorized` };
    context.response.headers.set('Content-Type', 'application/json');
    return context.response;
  }
  
  const deleted = db.DbLinks.deleteFile(shl.id, await currentFileHash.value);
  if (!db.DbLinks.linkExists(context.params.shlId)) {
    context.response.status = 500;
    context.response.body = { message: "Failed to delete file" };
    context.response.headers.set('Content-Type', 'application/json');
    return context.response;
  }
  const updatedShl = db.DbLinks.getUserShl(shl.id, userId)!;
  context.response.headers.set('Content-Type', 'application/json');
  context.response.body = prepareShlForReturn(updatedShl);
  return context.response;
});
/** Add endpoint to SHL */
router.post('/shl/:shlId/endpoint', async (context) => {
  const userId = context.state.auth.sub;
  const config: types.HealthLinkEndpoint = await context.request.body({ type: 'json' }).value;

  if (!db.DbLinks.linkExists(context.params.shlId)) {
    context.response.status = 404;
    context.response.body = { message: "SHL does not exist or has been deactivated." };
    context.response.headers.set('Content-Type', 'application/json');
    return context.response;
  }
  const shl = db.DbLinks.getUserShlInternal(context.params.shlId, userId)!;
  if (!shl) {
    context.response.status = 401;
    context.response.body = { message: `Unauthorized` };
    context.response.headers.set('Content-Type', 'application/json');
    return context.response;
  }

  const added = await db.DbLinks.addEndpoint(shl.id, config);
  console.log("Added", added)
  const updatedShl = db.DbLinks.getUserShl(context.params.shlId, userId)!;
  context.response.headers.set('Content-Type', 'application/json');
  context.response.body = prepareShlForReturn(updatedShl);
  return context.response;
});
/** Subscribe to SHLs related to a management token */
router.post('/subscribe', async (context) => {
  const shlSet: { shlId: string; managementToken: string }[] = await context.request.body({ type: 'json' }).value;
  const managedLinks = shlSet.map((req) => db.DbLinks.getManagedShl(req.shlId, req.managementToken));

  const ticket = randomStringWithEntropy(32, 'subscription-ticket-');
  subscriptionTickets.set(
    ticket,
    managedLinks.map((l) => l.id),
  );
  setTimeout(() => {
    subscriptionTickets.delete(ticket);
  }, 10000);
  context.response.body = { subscribe: `${env.PUBLIC_URL}/api/subscribe/${ticket}` };
  return context.response;
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
async function authMiddleware(ctx, next) {

  // TODO: temp - remove in favor of jwt
  // Adapter to handle user id in body
  try {
    const content = await ctx.request.body({ type: 'json' }).value;
    console.log(content);
    if (content.userId) {
      console.log("Using user id from body: " + content.userId);
      ctx.state.auth = { sub: content.userId };
      return next();
    }
    console.log("No user id in body");
    throw Error("No body");
  } catch (e) {
    console.log("No body, skipping userId check");
  }
  // temp

  const token = ctx.request.headers.get('Authorization');
  if (!token) {
    ctx.response.status = 400;
    ctx.response.body = { message: 'token missing' };
    return ctx.response;
  }

  const tokenValue = token.split(' ')[1];
  if (!tokenValue) {
    ctx.response.status = 400;
    ctx.response.body = { message: 'token missing' };
    return ctx.response;
  }

  // TODO: temp - remove in favor of jwt
  // Adapter to handle management token auth header
  if (db.DbLinks.managementTokenExists(tokenValue)) {
    console.log("Using management token: " + tokenValue);
    ctx.state.auth = { sub: db.DbLinks.getManagementTokenUserInternal(tokenValue) };
    console.log("User: " + ctx.state.auth.sub);
    return await next();
  }
  // temp

  const jwksClient = await fetch(env.JWKS_URL);
  const jwks = await jwksClient.json();

  const signingKey = jwks.keys.find((key) => key.kid === tokenValue.kid);
  if (!signingKey) {
    ctx.response.status = 401;
    ctx.response.body = { message: 'invalid token' };
    return ctx.response;
  }

  try {
    const decodedToken = await jose.jwtVerify(tokenValue, signingKey, {
      algorithms: ['RS256'],
      audience: ['account'],
    });
    ctx.state.auth = decodedToken.payload;
    
    return await next();
  
  } catch (error) {
    if (error instanceof jose.jwt.JWTExpired) {
      ctx.response.status = 401;
      ctx.response.body = { message: 'token expired' };
    } else {
      ctx.response.status = 401;
      ctx.response.body = { message: 'invalid token' };
    }
    return ctx.response;
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
  const subset = Object.fromEntries(
    Object.entries(flat).filter(([key]) => keys.includes(key))
  );
  console.log("Subset: " + JSON.stringify(subset));
  return subset;
}

function prepareShlForReturn(shl: types.HealthLinkFull) {
  let flat = {
    ...shl,
    ...shl.config,
  };
  delete flat.config;
  return flat;
}

export const shlApiRouter = router;
