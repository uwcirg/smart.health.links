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

export const shlApiRouter = new oak.Router()
  .post('/shl', async (context) => {
    const config: types.HealthLinkConfig = await context.request.body({ type: 'json' }).value;
    const newLink = db.DbLinks.create(config);
    console.log("Created link " + newLink.id);
    context.response.body = {
      ...newLink,
      files: undefined,
      config: undefined,
    };
  })
  .post('/shl/:shlId', async (context) => {
    const config: types.HealthLinkManifestRequest = await context.request.body({ type: 'json' }).value;
    const embeddedLengthMax = Math.min(env.EMBEDDED_LENGTH_MAX, config.embeddedLengthMax !== undefined ? config.embeddedLengthMax : Infinity);

    let shl: types.HealthLink;
    try {
      shl = db.DbLinks.getShlInternal(context.params.shlId);
    } catch {
      context.response.status = 404;
      context.response.body = { message: "SHL does not exist or has been deactivated."};
      context.response.headers.set('content-type', 'application/json');
      return;
    }

    if (!shl?.active) {
      context.response.status = 404;
      context.response.body = { message: "SHL does not exist or has been deactivated." };
      context.response.headers.set('content-type', 'application/json');
      return;
    }
    if (shl.config.exp && new Date(shl.config.exp * 1000).getTime() < new Date().getTime()) {
      context.response.status = 403;
      context.response.body = { message: "SHL is expired" };
      context.response.headers.set('content-type', 'application/json');
      return;
    }
    if (shl.config.passcode && !("passcode" in config)) {
      context.response.status = 401;
      context.response.body = {
        message: "Password required",
        remainingAttempts: shl.passcodeFailuresRemaining
      }
      context.response.headers.set('content-type', 'application/json');
      return;
    }
    if (shl.config.passcode && shl.config.passcode !== config.passcode) {
      db.DbLinks.recordPasscodeFailure(shl.id);
      context.response.status = 401;
      context.response.body = {
        message: "Incorrect password",
        remainingAttempts: shl.passcodeFailuresRemaining - 1
      };
      context.response.headers.set('content-type', 'application/json');
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
    context.response.body = {
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
    context.response.headers.set('content-type', 'application/json');
  })
  .put('/shl/:shlId', async (context) => {
    const managementToken = await context.request.headers.get('authorization')?.split(/bearer /i)[1]!;
    const config: types.HealthLinkConfig = await context.request.body({ type: 'json' }).value;
    if (!db.DbLinks.linkExists(context.params.shlId)) {
      context.response.status = 404;
      context.response.body = { message: "SHL does not exist or has been deactivated." };
      context.response.headers.set('content-type', 'application/json');
      return;
    }
    const shl = db.DbLinks.getManagedShl(context.params.shlId, managementToken)!;
    if (!shl) {
      context.response.status = 401;
      context.response.body = { message: `Unauthorized` };
      context.response.headers.set('content-type', 'application/json');
      return;
    }
    shl.config.exp = config.exp ?? shl.config.exp;
    shl.config.passcode = config.passcode ?? shl.config.passcode;
    const updated = db.DbLinks.updateConfig(shl);
    const updatedShl = db.DbLinks.getManagedShl(context.params.shlId, managementToken)!;
    context.response.body = updatedShl;
    context.response.headers.set('content-type', 'application/json');
  })
  .get('/shl/:shlId/active', (context) => {
    const shl = db.DbLinks.getShlInternal(context.params.shlId);
    if (!shl) {
      context.response.status = 404;
      context.response.body = { message: `Deleted` };
      context.response.headers.set('content-type', 'application/json');
      return;
    }
    const isActive = (shl && shl.active);
    console.log(context.params.shlId + " active: " + isActive);
    context.response.body = isActive;
    context.response.headers.set('content-type', 'application/json');
    return;
  })
  .put('/shl/:shlId/reactivate', async (context) => {
    const managementToken = await context.request.headers.get('authorization')?.split(/bearer /i)[1]!;
    const success = db.DbLinks.reactivate(context.params.shlId, managementToken)!;
    console.log("Reactivated " + context.params.shlId + ": " + success);
    context.response.headers.set('content-type', 'application/json');
    return (context.response.body = success);
  })
  .get('/shl/:shlId/file/:fileIndex', (context) => {
    const ticket = manifestAccessTickets.get(context.request.url.searchParams.get('ticket')!);
    if (!ticket) {
      console.log('Cannot request SHL without a valid ticket');
      context.response.status = 401;
      context.response.body = { message: "Unauthorized" }
      context.response.headers.set('content-type', 'application/json');
      return;
    }

    if (ticket.shlId !== context.params.shlId) {
      console.log('Ticket is not valid for ' + context.params.shlId);
      context.response.status = 401;
      context.response.body = { message: "Unauthorized" }
      context.response.headers.set('content-type', 'application/json');
      return;
    }

    const file = db.DbLinks.getFile(context.params.shlId, context.params.fileIndex);
    context.response.headers.set('content-type', 'application/jose');
    context.response.body = file.content;
  })
  .get('/shl/:shlId/endpoint/:endpointId', async (context) => {
    const ticket = manifestAccessTickets.get(context.request.url.searchParams.get('ticket')!);
    if (!ticket) {
      console.log('Cannot request SHL without a valid ticket');
      context.response.status = 401;
      context.response.body = { message: "Unauthorized" }
      context.response.headers.set('content-type', 'application/json');
      return;
    }

    if (ticket.shlId !== context.params.shlId) {
      console.log('Ticket is not valid for ' + context.params.shlId);
      context.response.status = 401;
      context.response.body = { message: "Unauthorized" };
      context.response.headers.set('content-type', 'application/json');
      return;
    }

    const endpoint = await db.DbLinks.getEndpoint(context.params.shlId, context.params.endpointId);
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
  })
  .post('/shl/:shlId/file', async (context) => {
    const managementToken = await context.request.headers.get('authorization')?.split(/bearer /i)[1]!;
    const newFileBody = await context.request.body({
      type: 'bytes',
      limit: fileSizeMax
    });

    if (!db.DbLinks.linkExists(context.params.shlId)) {
      context.response.status = 404;
      context.response.body = { message: "SHL does not exist or has been deactivated." };
      context.response.headers.set('content-type', 'application/json');
      return;
    }
    const shl = db.DbLinks.getManagedShl(context.params.shlId, managementToken)!;
    if (!shl) {
      context.response.status = 401;
      context.response.body = { message: `Unauthorized` };
      context.response.headers.set('content-type', 'application/json');
      return;
    }

    let contentLength = context.request.headers.get('content-length');
    if (contentLength === null) {
      context.response.status = 400;
      context.response.body = { message: `Missing content length` };
      context.response.headers.set('content-type', 'application/json');
      return;
    }
    if (Number(contentLength) > fileSizeMax) {
      context.response.status = 413;
      context.response.body = { message: `Size limit exceeded` };
      context.response.headers.set('content-type', 'application/json');
      return;
    }

    const newFile = {
      contentType: context.request.headers.get('content-type')!,
      content: await newFileBody.value,
    };

    const added = db.DbLinks.addFile(shl.id, newFile);
    context.response.body = {
      ...shl,
      added,
    };
  })
  .delete('/shl/:shlId/file', async (context) => {
    const managementToken = await context.request.headers.get('authorization')?.split(/bearer /i)[1]!;
    const currentFileBody = await context.request.body({type: 'bytes'});
    if (!db.DbLinks.linkExists(context.params.shlId)) {
      context.response.status = 404;
      context.response.body = { message: "SHL does not exist or has been deactivated." };
      context.response.headers.set('content-type', 'application/json');
      return;
    }
    const shl = db.DbLinks.getManagedShl(context.params.shlId, managementToken)!;
    if (!shl) {
      context.response.status = 401;
      context.response.body = { message: `Unauthorized` };
      context.response.headers.set('content-type', 'application/json');
      return;
    }
    
    const deleted = db.DbLinks.deleteFile(shl.id, await currentFileBody.value);
    context.response.body = {
      ...shl,
      deleted,
    }
    context.response.headers.set('content-type', 'application/json');
  })
  .post('/shl/:shlId/endpoint', async (context) => {
    const managementToken = await context.request.headers.get('authorization')?.split(/bearer /i)[1]!;
    const config: types.HealthLinkEndpoint = await context.request.body({ type: 'json' }).value;

    if (!db.DbLinks.linkExists(context.params.shlId)) {
      context.response.status = 404;
      context.response.body = { message: "SHL does not exist or has been deactivated." };
      context.response.headers.set('content-type', 'application/json');
      return;
    }
    const shl = db.DbLinks.getManagedShl(context.params.shlId, managementToken)!;
    if (!shl) {
      context.response.status = 401;
      context.response.body = { message: `Unauthorized` };
      context.response.headers.set('content-type', 'application/json');
      return;
    }

    const added = await db.DbLinks.addEndpoint(shl.id, config);
    console.log("Added", added)
    context.response.body = {
      ...shl,
      added,
    };
  })
  .delete('/shl/:shlId', async (context) => {
    const managementToken = await context.request.headers.get('authorization')?.split(/bearer /i)[1]!;
    if (!db.DbLinks.linkExists(context.params.shlId)) {
      context.response.status = 404;
      context.response.body = { message: "SHL does not exist or has been deactivated." };
      context.response.headers.set('content-type', 'application/json');
      return;
    }
    try {
      const shl = db.DbLinks.getManagedShl(context.params.shlId, managementToken)!;
      if (!shl) {
        context.response.status = 401;
        context.response.body = { message: `Unauthorized` };
        context.response.headers.set('content-type', 'application/json');
        return;
      }
      const deactivated = db.DbLinks.deactivate(shl);
      context.response.body = deactivated;
    } catch {
      context.response.status = 404;
      context.response.body = { message: "SHL does not exist" };
      context.response.headers.set('content-type', 'application/json');
      return;
    }
  })
  .post('/subscribe', async (context) => {
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
  })
  .get('/subscribe/:ticket', (context) => {
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
  })
  .post('/iis', async(context) => {
    const content = await context.request.body({ type: 'json' }).value;
    const response = await fetch('http://35.160.125.146:8039/fhir/Patient/', {
      method: 'POST',
      headers: content.headers,
      body: JSON.stringify(content)
    });
    if (response.ok) {
      const body = await response.json();
      context.response.body = body;
    } else {
      throw new Error('Unable to fetch IIS immunization data');
    };
  });

/*
  .post('/register', (context) => {
  })
  /*
    files: DbLinks.fileNames(client.shlink).map(
            (f, _i) => ({contentType: f.contentType, location: `${env.PUBLIC_URL}/api/shl/${client.shlink}/file/${f}`}),
    ),

  */
