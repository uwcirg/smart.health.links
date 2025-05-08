// deno-lint-ignore-file no-explicit-any
import env from '../config.ts';
import { jose, base64url } from '../deps.ts';
import * as types from '../types.ts';
import { randomStringWithEntropy } from '../util.ts';
import * as assertions from 'https://deno.land/std@0.133.0/testing/asserts.ts';

import app from '../server.ts';
await app;

const usershls: Record<string, types.HealthLinkFull> = {};

async function initializeTest(config: types.HealthLinkConfig = {}) {
  assertions.assertExists(config.userId);
  await createSHL(config);
  await updateUserShls(config.userId);
  await addSHCFile(config.userId);
  await updateUserShls(config.userId);
}

async function createSHL(config: types.HealthLinkConfig = {}) {
  // console.log('Public URL: ' + env.PUBLIC_URL);
  const shlResponse = await fetch(`${env.PUBLIC_URL}/api/shl`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
    },
    body: JSON.stringify(config),
  });
  const result = await shlResponse.text();
  // console.log('Created ', result);
  assertions.assertEquals(shlResponse.status, 200);
  assertions.assertEquals(result.indexOf('shlink:/'), 0);
  const decoded = base64url.decode(result.split('/')[1]);
  const asString = new TextDecoder('utf-8').decode(decoded);
  // console.log('New SHL: ' + asString);
  const newSHL = JSON.parse(asString);
  assertions.assertExists(newSHL.id);
  assertions.assertExists(newSHL.url);
  assertions.assertExists(newSHL.key);
  assertions.assertEquals(newSHL.flag, 'P');
  return newSHL as types.SHLDecoded;
}

async function updateUserShls(userId: string) {
  const shlsResponse = await fetch(`${env.PUBLIC_URL}/api/user`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
    },
    body: JSON.stringify({ userId: userId }),
  });
  assertions.assertEquals(shlsResponse.status, 200);

  const result = await shlsResponse.text();
  // console.log('User SHLs: ' + result);
  const shls = JSON.parse(result) as types.HealthLinkFull[];
  if (shls.length > 0) {
    usershls[userId] = shls[0];
  }
  // console.log("User SHL: " + JSON.stringify(usershl));
}

function getUserSHL(userId: string) {
  const shl = usershls[userId];
  assertions.assertExists(shl);
  return shl;
}

async function addSHCFile(userId:string, shlid?:string) {
  const shl = getUserSHL(userId);

  const decrypt = randomStringWithEntropy(32);
  const key = jose.base64url.decode(decrypt);
  const plaintextFile = JSON.stringify({
    verifiableCredential: [
      'eyJ6aXAiOiJERUYiLCJhbGciOiJFUzI1NiIsImtpZCI6IjNLZmRnLVh3UC03Z1h5eXd0VWZVQUR3QnVtRE9QS01ReC1pRUxMMTFXOXMifQ.pZJLb9swEIT_SrC9ynrYSozq2PaQnBIgjx4KH2hqbbHgQ1hSbtxA_727jIMERZBLAB1EcvhxZsgnMDFCB0NKY-yqKo6oy-gUpQGVTUOpFfWxwkflRouxYvWEBAX47Q665qL9Wi_r1bItl-tVAQcN3ROk44jQ_Xpl_o_78jxYyIBRn9cZ5yZv_qpkgodNAZqwR5-MsrfT9jfqJLZ2g6EHpCiaDtqyLhuGyuy3yfcWRUMYw0Qa73IEOC0Up0igg7VME0IBfAAdOSeTJ2vvybLgZX9Xs-Bl8A74hq3yfulROXyGKGfsUQ6l8Ef4e3NALz1eW_4j2MycbGs4-g-VBLKsm_WibhZ1C_NcvGuj-djG1dveCohJpSnmnHLbCaX1g9LaePwe-kzQoTd-nx3HY0zoTo-H72Ww6zLQvpJKq2j6Sh8eGaDzTmjaC5g3cwHjKXu2s0NCL97eVseioPVEeUnC3hn3Gni1qM8ZOyLtAjkuRrwonQIJsjdxtEp6vP95dpkfydkN9kYlMpp72uRvnv8B.xMOa6WDbATD-kxUeCwPWFPOOy9vjERhr674vxlnganYP7LVgdLbyt4vyZzpimh-5Uxn-AZs5GuuXvbIq3wPyJg',
    ],
  });
  const encryptedFile = await new jose.CompactEncrypt(new TextEncoder().encode(plaintextFile))
    .setProtectedHeader({
      alg: 'dir',
      enc: 'A256GCM',
    })
    .encrypt(key);

  const shlFileResponse = await fetch(`${env.PUBLIC_URL}/api/shl/${shl!.id}/file`, {
    method: 'POST',
    headers: {
      'content-type': 'application/smart-health-card',
      authorization: `Bearer ${shl.managementToken}`,
    },
    body: encryptedFile,
  });

  assertions.assertEquals(shlFileResponse.status, 200);
}

async function addJSONFile(userId:string) {
  const shl = getUserSHL(userId);

  const shlFileResponse = await fetch(`${env.PUBLIC_URL}/api/shl/${shl!.id}/file`, {
    method: 'POST',
    headers: {
      'content-type': 'application/fhir+json',
      authorization: `Bearer ${shl.managementToken}`,
    },
    body: JSON.stringify({
      resourceType: 'Patient',
      name: 'John Doe',
    })
  });
  assertions.assertEquals(shlFileResponse.status, 200);
}

async function getManifest(id: string, body: types.HealthLinkManifestRequest) {
  const manifestResponse = await fetch(`${env.PUBLIC_URL}/api/shl/${id}`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
    },
    body: JSON.stringify(body),
  });

  return manifestResponse;
}

Deno.test({
  name: 'Create SHL',
  async fn(t) {
    const userId = randomStringWithEntropy(32);
    let newSHL: types.SHLDecoded;
    await t.step('Create a SHL', async function() {
      newSHL = await createSHL({ userId });
    });
    await t.step('Get user shls', async function () {
      await updateUserShls(userId);
      const shl = usershls[userId];
      assertions.assertExists(shl);
      assertions.assert(shl.id === newSHL.id);
      assertions.assertExists(shl?.files);
    });

    await t.step('Add a SHC file to SHL', () => addSHCFile(userId));

    await t.step('Update user shls', async function () {
      await updateUserShls(userId);
      const shl: types.HealthLinkFull = usershls[userId];
      assertions.assert(shl?.files.length === 1);
      assertions.assert(shl?.files[0].contentType === 'application/smart-health-card');
      assertions.assert(shl?.files[0].contentHash.length > 0);
      usershls[userId] = shl;
      // console.log("Updated user SHL: " + JSON.stringify(shl));
    });
  },
  sanitizeOps: false,
  sanitizeResources: false,
});

Deno.test({
  name: 'App supports e2e flow',
  async fn(t) {
    const userId = randomStringWithEntropy(32);
    await initializeTest({ userId: userId, passcode: '1234' });
    let shl = usershls[userId];
    assertions.assertExists(shl);

    let sseRequest: Response;
    await t.step('Subscribe to SHL', async function () {
      const sseTicketRequest = await fetch(`${env.PUBLIC_URL}/api/subscribe`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${shl.managementToken}`,
        },
        body: JSON.stringify([
          {
            shlId: shl!.id,
            managementToken: shl!.managementToken,
          },
        ]),
      });
  
      const sseTicket = await sseTicketRequest.json();
      // console.log("SSE ticket endpoint: " + sseTicket.subscribe);
  
      sseRequest = await fetch(sseTicket.subscribe, {
        method: 'GET',
        headers: {
          authorization: `Bearer ${shl.managementToken}`,
          accept: 'text/event-stream',
        },
      });
    });

    let manifestJson: any;
    await t.step('Obtain manifest from SHL server', async function () {
      const manifestResponse = await getManifest(
        shl!.id,
        { passcode: '1234', recipient: 'Test SHL Client' }
      );

      assertions.assertEquals(manifestResponse.status, 200);
      manifestJson = await manifestResponse.json();
      // console.log('Access Token Response');
      // console.log(JSON.stringify(tokenResponseJson, null, 2));
    });

    await t.step('Ensure event subscriptions announce a new manifest request', async function () {
      const sseReader = sseRequest.body?.getReader();
      const readEvent = await sseReader?.read().then(function readChunk(v) {
        const [eventType, eventBody] = new TextDecoder().decode(v.value).split(/\n/, 2);
        return { type: eventType.split(': ', 2)[1], body: JSON.parse(eventBody.split(': ', 2)[1]) };
      });
      assertions.assert(readEvent?.type === 'status');
      assertions.assert(readEvent?.body.id === shl.id && readEvent.body.active);
    });

    await t.step('Download SHC file using access token', async function () {
      assertions.assert(manifestJson.files[0].contentType === 'application/smart-health-card');
      console.log(manifestJson.files[0].location);
      const fileResponse = await fetch(manifestJson.files[0].location);
      const file = await fileResponse.text();
      assertions.assert(file.length > 2);
    });
  },
  sanitizeOps: false,
  sanitizeResources: false,
});

Deno.test({
  name: 'Manifest Interactions',
  async fn(t) {
    const userId = randomStringWithEntropy(32);
    let passcode = '1234';
    await initializeTest({ userId: userId, passcode: passcode });
    const shl = getUserSHL(userId);

    await t.step('Get manifest', async function () {
      const manifestResponse = await getManifest(
        shl!.id,
        { passcode: passcode, recipient: 'Test SHL Client' }
      );
      assertions.assertEquals(manifestResponse.status, 200);
      const manifest = await manifestResponse.json();
      assertions.assertExists(manifest.files);
      assertions.assertExists(manifest.files[0].contentType);
      assertions.assertExists(manifest.files[0].location);
    });

    await t.step('Request manifest with wrong passcode', async function () {
      const manifestResponse = await getManifest(
        shl!.id,
        { passcode: 'wrong', recipient: 'Test SHL Client' }
      );
      const manifestContent = await manifestResponse.json();
      assertions.assertEquals(manifestResponse.status, 401);
      assertions.assertExists((manifestContent).details.remainingAttempts);
      assertions.assert((manifestContent).details.remainingAttempts > 0);
    });
    await t.step('Request manifest with missing passcode', async function () {
      const manifestResponse = await getManifest(
        shl!.id,
        { recipient: 'Test SHL Client' }
      );
      assertions.assertEquals(manifestResponse.status, 401);
    });
    await t.step('Request manifest with missing recipient', async function () {
      const manifestResponse = await getManifest(
        shl!.id,
        // @ts-ignore
        { passcode: passcode }
      );
      assertions.assertEquals(manifestResponse.status, 400);
    });
    await t.step('Request manifest for non-existent SHL id', async function () {
      const manifestResponse = await getManifest(
        'non-existent-shl-id',
        { passcode: passcode, recipient: 'Test SHL Client' }
      );
      assertions.assertEquals(manifestResponse.status, 404);
    });
  },
  sanitizeOps: false,
  sanitizeResources: false,
});

Deno.test({
  name: 'Configuration Interactions',
  async fn(t) {
    const userId = randomStringWithEntropy(32);
    const ogPasscode = '1234';
    const expiration = new Date().getTime() / 1000 + (60 * 60 * 24); // one day in the future
    const label = 'Test SHL';

    await initializeTest({
      userId: userId,
      passcode: ogPasscode,
      exp: expiration,
      label: label,
    });
    const shl = getUserSHL(userId);
    assertions.assertEquals(shl.config.passcode, ogPasscode);
    assertions.assertEquals(shl.config.exp, shl.config.exp);
    assertions.assertEquals(shl.label, label);

    await t.step('Change label', async function () {
      const putResponse = await fetch(`${env.PUBLIC_URL}/api/shl/${shl!.id}`, {
        method: 'PUT',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${shl.managementToken}`,
        },
        body: JSON.stringify({
          label: 'New Label',
        })
      });
      assertions.assertEquals(putResponse.status, 200);
    });
    await updateUserShls(userId);
    assertions.assertEquals(getUserSHL(userId).label, 'New Label');

    const newPasscode = '5678';
    await t.step('Change passcode', async function () {
      const putResponse = await fetch(`${env.PUBLIC_URL}/api/shl/${shl!.id}`, {
        method: 'PUT',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${shl.managementToken}`,
        },
        body: JSON.stringify({
          passcode: newPasscode,
        }),
      });
      assertions.assertEquals(putResponse.status, 200);
    });
    await t.step('Fetch manifest using old passcode', async function () {
      const manifestResponse = await getManifest(
        shl!.id,
        { passcode: ogPasscode, recipient: 'Test SHL Client' }
      );
      assertions.assertEquals(manifestResponse.status, 401);
    });
    await t.step('Fetch manifest using new passcode', async function () {
      const manifestResponse = await getManifest(
        shl!.id,
        { passcode: newPasscode, recipient: 'Test SHL Client' }
      );
      assertions.assertEquals(manifestResponse.status, 200);
    });

    await t.step('Expire SHL', async function () {
      const putResponse = await fetch(`${env.PUBLIC_URL}/api/shl/${shl!.id}`, {
        method: 'PUT',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${shl.managementToken}`,
        },
        body: JSON.stringify({
          exp: new Date().getTime() / 1000 - (10000), // a while ago
        }),
      });
      assertions.assertEquals(putResponse.status, 200);
    });
    await t.step('Fetch expired SHL manifest', async function () {
      const manifestResponse = await getManifest(
        shl!.id,
        { passcode: newPasscode, recipient: 'Test SHL Client' }
      );
      assertions.assertEquals(manifestResponse.status, 404);
    });

    await t.step('Update nonexistent SHL', async function () {
      const putResponse = await fetch(`${env.PUBLIC_URL}/api/shl/nonexistent-shl-id`, {
        method: 'PUT',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${shl.managementToken}`,
        },
        body: JSON.stringify({
          passcode: 'passcode',
        }),
      });
      assertions.assertEquals(putResponse.status, 404);
    });
  },
  sanitizeOps: false,
  sanitizeResources: false,
});

Deno.test({
  name: 'Active Status Interactions',
  async fn(t) {
    const userId = randomStringWithEntropy(32);
    await initializeTest({ userId: userId, passcode: '1234' });
    const shl = getUserSHL(userId);
    
    await t.step('Check shl active status (active)', async function () {
      const activeResponse = await fetch(`${env.PUBLIC_URL}/api/shl/${shl!.id}/active`, {
        method: 'GET',
        headers: {
          'content-type': 'application/json',
        },
      });
      assertions.assertEquals(activeResponse.status, 200);
      assertions.assertEquals(await activeResponse.json(), true);
    });

    await t.step('Deactivate SHL', async function () {
      const deactivateResponse = await fetch(`${env.PUBLIC_URL}/api/shl/${shl!.id}`, {
        method: 'DELETE',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${shl.managementToken}`,
        },
      });
      assertions.assertEquals(deactivateResponse.status, 200);
    });

    await t.step('Check shl active status (inactive)', async function () {
      const activeResponse = await fetch(`${env.PUBLIC_URL}/api/shl/${shl!.id}/active`, {
        method: 'GET',
        headers: {
          'content-type': 'application/json',
        },
      });
      assertions.assertEquals(activeResponse.status, 200);
      assertions.assertEquals(await activeResponse.json(), false);
    });

    await t.step('Request inactive SHL manifest', async function () {
      const manifestResponse = await fetch(`${env.PUBLIC_URL}/api/shl/${shl!.id}`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          passcode: '5678',
          recipient: 'Test SHL Client',
        }),
      });
      assertions.assertEquals(manifestResponse.status, 404);
    });

    await t.step('Re-activate SHL', async function () {
      const activateResponse = await fetch(`${env.PUBLIC_URL}/api/shl/${shl!.id}/reactivate`, {
        method: 'PUT',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${shl.managementToken}`,
        },
      });
      assertions.assertEquals(activateResponse.status, 200);
    });

    await t.step('Check shl active status (reactivated)', async function () {
      const activeResponse = await fetch(`${env.PUBLIC_URL}/api/shl/${shl!.id}/active`, {
        method: 'GET',
        headers: {
          'content-type': 'application/json',
        },
      });
      assertions.assertEquals(activeResponse.status, 200);
      assertions.assertEquals(await activeResponse.json(), true);
    });

    await t.step('Deactivate nonexistant SHL', async function () {
      const deactivateResponse = await fetch(`${env.PUBLIC_URL}/api/shl/nonexistent-shl-id`, {
        method: 'DELETE',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${shl.managementToken}`,
        },
      });
      assertions.assertEquals(deactivateResponse.status, 404);
    });
    await t.step('Re-activate nonexistant SHL', async function () {
      const activateResponse = await fetch(`${env.PUBLIC_URL}/api/shl/nonexistent-shl-id/reactivate`, {
        method: 'PUT',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${shl.managementToken}`,
        },
      });
      assertions.assertEquals(activateResponse.status, 401);
    });
  },
  sanitizeOps: false,
  sanitizeResources: false,
});

Deno.test({
  name: 'SHL File Interactions',
  async fn(t) {
    const userId = randomStringWithEntropy(32);
    await initializeTest({ userId: userId, passcode: '1234' });
    let shl = getUserSHL(userId);
    let manifestJson: types.SHLinkManifest;

    await t.step('Get SHL manifest', async function () {
      const manifestResponse = await getManifest(
        shl!.id,
        { passcode: '1234', recipient: 'Test SHL Client' }
      );
      assertions.assertEquals(manifestResponse.status, 200);
      manifestJson = await manifestResponse.json();
      assertions.assertExists(manifestJson.files);
      assertions.assertEquals(manifestJson.files.length, 1);
      
      const file = manifestJson.files[0];
      assertions.assertExists(file.location);
      assertions.assertExists(file.contentType);
    });
    await t.step('Download SHC file using access token', async function () {
      assertions.assert(manifestJson.files[0].contentType === 'application/smart-health-card');
      const fileResponse = await fetch(manifestJson.files[0].location);
      const file = await fileResponse.text();
      assertions.assert(file.length > 2);
    });

    await t.step('Add JSON file to SHL', async function () {
      await addJSONFile(userId);
      const manifestResponse = await getManifest(
        shl!.id,
        { passcode: '1234', recipient: 'Test SHL Client' }
      );
      manifestJson = await manifestResponse.json();
      assertions.assertEquals(manifestJson.files.length, 2);
      await updateUserShls(userId);
      shl = getUserSHL(userId);
    });
    await t.step('Get SHL manifest (2 files)', async function () {
      const manifestResponse = await getManifest(
        shl!.id,
        { passcode: '1234', recipient: 'Test SHL Client' }
      );
      assertions.assertEquals(manifestResponse.status, 200);
      manifestJson = await manifestResponse.json();
      assertions.assertExists(manifestJson.files);
      assertions.assertEquals(manifestJson.files.length, 2);
      
      const file = manifestJson.files[1];
      assertions.assertExists(file.location);
      assertions.assertExists(file.contentType);
      assertions.assert(file.contentType === 'application/fhir+json');
    });
    await t.step('Download JSON file using access token', async function () {
      const fileResponse = await fetch(manifestJson.files[1].location);
      const file = await fileResponse.text();
      assertions.assert(file.length > 2);
    });

    await t.step('Delete JSON file from SHL', async function () {
      const deleteResponse = await fetch(`${env.PUBLIC_URL}/api/shl/${shl!.id}/file`, {
        method: 'DELETE',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${shl.managementToken}`,
        },
        body: shl.files[1].contentHash,
      });
      assertions.assertEquals(deleteResponse.status, 200);
      await updateUserShls(userId);
      shl = getUserSHL(userId);
    });

    await t.step('Get SHL manifest (1 files)', async function () {
      const manifestResponse = await getManifest(
        shl!.id,
        { passcode: '1234', recipient: 'Test SHL Client' }
      );
      assertions.assertEquals(manifestResponse.status, 200);
      manifestJson = await manifestResponse.json();
      assertions.assertExists(manifestJson.files);
      assertions.assertEquals(manifestJson.files.length, 1);
      
      const file = manifestJson.files[0];
      assertions.assertExists(file.location);
      assertions.assertExists(file.contentType);
      assertions.assert(file.contentType === 'application/smart-health-card');
    });

    await t.step('Request SHL files witout ticket', async function () {
      const fileResponse = await fetch(manifestJson.files[0].location.replace(/ticket=.*/, ''));
      assertions.assertEquals(fileResponse.status, 401);
    });

    await t.step('Request SHL files with invalid ticket', async function () {
      let invalidTicketUrl = manifestJson.files[0].location.replace(/ticket=.*/, 'ticket=invalid-ticket');
      const fileResponse = await fetch(invalidTicketUrl);
      assertions.assertEquals(fileResponse.status, 401);
    });

    await t.step('Delete SHC file from SHL', async function () {
      const deleteResponse = await fetch(`${env.PUBLIC_URL}/api/shl/${shl!.id}/file`, {
        method: 'DELETE',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${shl.managementToken}`,
        },
        body: shl.files[0].contentHash,
      });
      assertions.assertEquals(deleteResponse.status, 200);
      await updateUserShls(userId);
      shl = getUserSHL(userId);
    });

    await t.step('Get SHL manifest (no files)', async function () {
      const manifestResponse = await getManifest(
        shl!.id,
        { passcode: '1234', recipient: 'Test SHL Client' }
      );
      assertions.assertEquals(manifestResponse.status, 200);
      manifestJson = await manifestResponse.json();
      assertions.assertExists(manifestJson.files);
      assertions.assertEquals(manifestJson.files.length, 0);
    });

    await t.step('Add SHC file to nonexistent SHL', async function () {
      const shlFileResponse = await fetch(`${env.PUBLIC_URL}/api/shl/nonexistent-shl/file`, {
        method: 'POST',
        headers: {
          'content-type': 'application/fhir+json',
          authorization: `Bearer ${shl.managementToken}`,
        },
        body: JSON.stringify({
          resourceType: 'Patient',
          name: 'John Doe',
        })
      });
      assertions.assertEquals(shlFileResponse.status, 404);
    });
    await t.step('Add SHC file to nonexistent user SHL', async function () {
      const shlFileResponse = await fetch(`${env.PUBLIC_URL}/api/shl/${shl!.id}/file`, {
        method: 'POST',
        headers: {
          'content-type': 'application/fhir+json',
          authorization: `Bearer bad-token`,
        },
        body: JSON.stringify({
          resourceType: 'Patient',
          name: 'John Doe',
        })
      });
      assertions.assertEquals(shlFileResponse.status, 401);
    });

    await t.step('Delete nonexistent file from SHL', async function () {
      const deleteResponse = await fetch(`${env.PUBLIC_URL}/api/shl/${shl!.id}/file`, {
        method: 'DELETE',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${shl.managementToken}`,
        },
        body: 'bad-hash',
      });
      assertions.assertEquals(deleteResponse.status, 200);
      await updateUserShls(userId);
      shl = getUserSHL(userId);
    });
    await t.step('Delete file from nonexistent SHL', async function () {
      const deleteResponse = await fetch(`${env.PUBLIC_URL}/api/shl/nonexistent-shl/file`, {
        method: 'DELETE',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${shl.managementToken}`,
        },
        body: 'bad-hash',
      });
      assertions.assertEquals(deleteResponse.status, 404);
      await updateUserShls(userId);
      shl = getUserSHL(userId);
    });
    await t.step('Delete nonexistent file from SHL', async function () {
      const deleteResponse = await fetch(`${env.PUBLIC_URL}/api/shl/${shl!.id}/file`, {
        method: 'DELETE',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer bad-token`,
        },
        body: 'bad-hash',
      });
      assertions.assertEquals(deleteResponse.status, 401);
      await updateUserShls(userId);
      shl = getUserSHL(userId);
    });
  },
  sanitizeOps: false,
  sanitizeResources: false,
})

Deno.test({
  name: 'Unauthorized user',
  async fn(t) {
    await updateUserShls('non-existent-user-id');
    assertions.assertEquals(Object.keys(usershls).includes('non-existent-user-id'), false);
  },
  sanitizeOps: false,
  sanitizeResources: false,
})

Deno.test({
  ignore: !Deno.env.get("TEST_SMART"),
  name: 'App supports SMART API Endpoints with Refresh',
  async fn(t) {
    const decrypt = randomStringWithEntropy(32);
    const key = jose.base64url.decode(decrypt);

    let shl: types.HealthLink;
    await t.step('Create a SHL', async function () {
      const shlResponse = await fetch(`${env.PUBLIC_URL}/api/shl`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          passcode: '1234',
        }),
      });

      assertions.assertEquals(shlResponse.status, 200);
      shl = (await shlResponse.json()) as types.HealthLink;
    });

    const accessConfig =  JSON.parse(await Deno.readTextFile("tests/smart-api-config.json"));

    const tokenResponse = { ...accessConfig.tokenResponse, referesh_token: undefined };
    const endpoint: types.HealthLinkEndpoint = {
      config: {
        clientId: accessConfig.clientId,
        clientSecret: accessConfig.clientSecret,
        key: decrypt,
        refreshToken: accessConfig.tokenResponse.refresh_token,
        tokenEndpoint: accessConfig.tokenUri,
      },
      endpointUrl: accessConfig.serverUrl.replace(/\/$/, ''),
      accessTokenResponse: tokenResponse,
    };

    await t.step('Add endpoint to SHL', async function () {
      const shlFileResponse = await fetch(`${env.PUBLIC_URL}/api/shl/${shl!.id}/endpoint`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${shl.managementToken}`,
        },
        body: JSON.stringify(endpoint),
      });

      assertions.assertEquals(shlFileResponse.status, 200);
      // console.log;
    });

    let manifestJson: types.SHLinkManifest;

    await t.step('Obtain manifest from SHL server', async function () {
      const manifestResponse = await fetch(`${env.PUBLIC_URL}/api/shl/${shl!.id}`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          passcode: '1234',
          recipient: 'Test SHL Client',
        }),
      });

      assertions.assertEquals(manifestResponse.status, 200);
      manifestJson = await manifestResponse.json();

      // console.log('Manifest response');
      // console.log(JSON.stringify(manifestJson, null, 2));
      assertions.assert(manifestJson.files.length === 1, 'Expected one endpoint in manifest');
    });

    async function fetchEndpoint(){
      assertions.assert(manifestJson.files[0].contentType === 'application/smart-api-access');
      const fileResponse = await fetch(manifestJson.files[0].location);
      const file = await fileResponse.text();

      const decrypted = await jose.compactDecrypt(file, key);
      const decoded = JSON.parse(new TextDecoder().decode(decrypted.plaintext));
      assertions.assertExists(decoded.access_token)
    }

    await t.step('Download SHC endpoint once', fetchEndpoint );
    await t.step('Download SHC endpoint again', fetchEndpoint );
  },
  sanitizeOps: false,
  sanitizeResources: false,
});
