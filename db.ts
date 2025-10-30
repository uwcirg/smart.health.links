import { base64url, fs, queryString, sqlite } from './deps.ts';
import { clientConnectionListener } from './routers/api.ts';
import * as types from './types.ts';
import { randomStringWithEntropy } from './util.ts';
import env from './config.ts';

const { DB } = sqlite;

const dir = env.DIR || '.';

let db = await initializeDb();

export async function initializeDb() {
  try {
    await fs.ensureDir(dir + '/db');
    await Deno.stat(dir + '/db/vaxx.db');
    console.log('DB file already exists');
    if (Deno.env.get('TEST')) {
      // clear the db for testing
      const file = await Deno.open(dir + '/db/vaxx.db', { create: true, write: true, truncate: true });
      await file.close();
    }
  } catch (err) {
    if (err instanceof Deno.errors.NotFound) {
      console.log('Creating DB file');
      const file = await Deno.open(dir + '/db/vaxx.db', { create: true, write: true });
      await file.close();
    } else {
      throw err;
    }
  }
  const db = new DB(dir + '/db/vaxx.db');
  const schema = await Deno.readTextFile('./schema.sql');
  schema.split(/\n\n/).forEach((q) => {
    try {
      db.execute(q);
    } catch (e) {
      if (!q.match('ok_to_fail')) throw e;
    }
  });
  return db;
}

async function updateAccessToken(endpoint: types.HealthLinkEndpointContent) {
  let updatedEndpoint = endpoint;
  const accessTokenRequest = await fetch(endpoint.config.tokenEndpoint, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      authorization: `Basic ${btoa(`${endpoint.config.clientId}:${endpoint.config.clientSecret}`)}`,
    },
    body: queryString.stringify({ grant_type: 'refresh_token', refresh_token: endpoint.config.refreshToken }),
  });
  const accessTokenResponse = await accessTokenRequest.json();
  
  updatedEndpoint.accessTokenResponse = accessTokenResponse;
  if (updatedEndpoint?.accessTokenResponse?.refresh_token) {
    updatedEndpoint.config.refreshToken = updatedEndpoint.accessTokenResponse.refresh_token;
    delete updatedEndpoint.accessTokenResponse.refresh_token;
  }
  const TOKEN_LIFETIME_SECONDS = 300;
  updatedEndpoint.refreshTime = new Date(new Date().getTime() + TOKEN_LIFETIME_SECONDS * 1000).toISOString();
  return updatedEndpoint;
}

export const DbLinks = {
  createUserIfNotExists(userid: string) {
    return db.query(`INSERT or ignore INTO user (id) values (?)`, [userid]);
  },
  create(config: types.HealthLinkConfig, userId: string): types.HealthLinkFull {
    this.createUserIfNotExists(userId);
    const link = {
      config,
      id: randomStringWithEntropy(32),
      managementToken: randomStringWithEntropy(32),
      active: true,
    };
    db.query(
      `INSERT INTO shlink_access (id, management_token, active, config_exp, config_passcode)
      values (:id, :managementToken, :active, :exp, :passcode)`,
      {
        id: link.id,
        managementToken: link.managementToken,
        active: link.active,
        exp: link.config.exp,
        passcode: link.config.passcode,
      },
    );

    db.query(
      `INSERT INTO user_shlink (user, shlink)
      values (:user, :shlink)`,
      {
        user: userId,
        shlink: link.id,
      },
    );

    const link_public = {
      id: link.id,
      manifestUrl: `${env.PUBLIC_URL}/api/shl/${link.id}`,
      key: randomStringWithEntropy(32),
      flag: 'P',
      label: config.label,
      version: 1
    }

    db.query(
      `INSERT INTO shlink_public (shlink, manifest_url, encryption_key, flag, label, version)
      values (:shlink, :manifestUrl, :encryptionKey, :flag, :label, :version)`,
      {
        shlink: link_public.id,
        manifestUrl: link_public.manifestUrl,
        encryptionKey: link_public.key,
        flag: link_public.flag,
        label: link_public.label,
        version: link_public.version
      },
    );

    return {
      id: link_public.id as string,
      url: link_public.manifestUrl as string,
      key: link_public.key as string & { length: 43 },
      flag: link_public.flag as string,
      label: link_public.label as string,
      v: link_public.version as number,
      files: [],
      config: {
        exp: link.config.exp as number,
        passcode: link.config.passcode as string
      },
      managementToken: link.managementToken as string
    };
  },
  getConfig(shlId: string) {
    let shl;
    try {
      shl = db.prepareQuery(`SELECT * from shlink_access where shlink=?`).oneEntry([shlId]);
    } catch (e) {
      return undefined;
    }

    return {
      exp: shl.config_exp,
      passcode: shl.config_passcode,
      label: shl.label
    };
  },
  updateConfig(shl: types.HealthLinkFull) {
    let pub: types.shlink_public;
    try {
      pub = db.prepareQuery(`SELECT * from shlink_public where shlink=?`).oneEntry([shl.id]);
    } catch (e) {
      return undefined;
    }

    let newFlag = pub.flag;
    if (!pub.flag?.includes('P')) {
      newFlag = pub.flag + 'P';
    }
    db.transaction(() => {
      db.query(
        `UPDATE shlink_public set flag=:flag, label=:label where shlink=:id`,
        {
          id: shl.id,
          flag: newFlag ?? pub.flag,
          label: shl.label
        }
      );
      db.query(
        `UPDATE shlink_access set config_passcode=:passcode, config_exp=:exp where id=:id`,
        {
          id: shl.id,
          exp: shl.config.exp,
          passcode: shl.config.passcode
        }
      );
    });
    return true;
  },
  deactivate(shl: types.HealthLink) {
    try {
      db.query(`UPDATE shlink_access set active=false where id=?`, [shl.id]);
    } catch (e) {
      return false;
    }
    return shl.id;
  },
  reactivate(shl: types.HealthLink): boolean {
    db.query(`UPDATE shlink_access set active=true, passcode_failures_remaining=5 where id=?`, [shl.id]);
    return true;
  },
  linkExists(linkId: string): boolean {
    return db.query(`SELECT * from shlink_access where id=? and active=1`, [linkId]).length > 0;
  },
  userExists(userId: string): boolean {
    return db.query(`SELECT * from user where id=?`, [userId]).length > 0;
  },
  managementTokenExists(managementToken: string): boolean {
    return db.query(`SELECT * from shlink_access where management_token=?`, [managementToken]).length > 0;
  },
  getManagementTokenUserInternal(managementToken: string): string | undefined {
    try {
      const result = db.prepareQuery(
        `SELECT * from shlink_access JOIN user_shlink on shlink_access.id=user_shlink.shlink where management_token=?`
      ).oneEntry([managementToken]);
      return result.user as string;
    } catch (e) {
      return undefined;
    }
  },
  getShlInternal(linkId: string): types.HealthLink | undefined {
    try {
      const linkRow = db.prepareQuery(`SELECT * from shlink_access where id=?`).oneEntry([linkId]);
      return {
        id: linkRow.id as string,
        passcodeFailuresRemaining: linkRow.passcode_failures_remaining as number,
        active: Boolean(linkRow.active) as boolean,
        managementToken: linkRow.management_token as string,
        config: {
          exp: linkRow.config_exp as number,
          passcode: linkRow.config_passcode as string,
        },
      };
    } catch (e) {
      return undefined;
    }
  },
  getUserShlInternal(linkId: string, userId: string): types.HealthLink | undefined {
    try {
      const userRow = db
        .prepareQuery(`
          SELECT * from user_shlink where shlink=? and user=?`)
        .oneEntry([linkId, userId]); // throws if not found
      
      const linkRow = db
        .prepareQuery(`SELECT * from shlink_access where id=?`)
        .oneEntry([linkId]);

      return {
        id: linkRow.id as string,
        passcodeFailuresRemaining: linkRow.passcode_failures_remaining as number,
        active: Boolean(linkRow.active) as boolean,
        managementToken: linkRow.management_token as string,
        config: {
          exp: linkRow.config_exp as number,
          passcode: linkRow.config_passcode as string,
        },
      };
    } catch (e) {
      return undefined;
    }
  },
  getManagedShl(linkId: string, managementToken: string): types.HealthLink | undefined {
    try {
      const linkRow = db
        .prepareQuery(`SELECT * from shlink_access where id=? and management_token=?`)
        .oneEntry([linkId, managementToken]);

      return {
        id: linkRow.id as string,
        passcodeFailuresRemaining: linkRow.passcode_failures_remaining as number,
        active: Boolean(linkRow.active) as boolean,
        managementToken: linkRow.management_token as string,
        config: {
          exp: linkRow.config_exp as number,
          passcode: linkRow.config_passcode as string,
        },
      };
    } catch (e) {
      return undefined;
    }
  },
  getShlOwner(linkId: string): string | undefined {
    try {
      const result = db.prepareQuery(`SELECT * from user_shlink where shlink=?`).oneEntry([linkId]);
      return result.user as string;
    } catch (e) {
      return undefined;
    }
  },
  getUserShl(linkId: string, userId: string): types.HealthLinkFull | undefined {
    try {
      const row = db
        .prepareQuery(`
          SELECT
            shlink_public.*,
            shlink_access.config_passcode,
            shlink_access.config_exp,
            shlink_access.management_token
          FROM user_shlink
          JOIN shlink_public on shlink_public.shlink=user_shlink.shlink
          JOIN shlink_access on shlink_access.id=user_shlink.shlink
          WHERE
            user_shlink.user=?
            and user_shlink.shlink=?
            and shlink_access.active=1
          `)
        .oneEntry([userId, linkId]) as types.shlink_access & types.shlink_public;
      const userShl = {
        id: row.shlink as string,
        url: row.manifest_url as string,
        exp: row.config_exp as number,
        key: row.encryption_key as string & { length: 43 },
        flag: row.flag as string,
        label: row.label as string,
        v: row.version as number,
        files: this.getSHLFileSummaries(row.id),
        config: {
          exp: row.config_exp as number,
          passcode: row.config_passcode as string
        },
        managementToken: row.management_token as string
      };
      return userShl;
    } catch (e) {
      return undefined;
    }
  },
  getUserShls(userId: string): Array<types.HealthLinkFull> | undefined {
    const userPubShls = db
      .prepareQuery(`
        SELECT
          shlink_public.*,
          shlink_access.config_passcode,
          shlink_access.config_exp,
          shlink_access.management_token
        FROM user_shlink
        JOIN shlink_public on shlink_public.shlink=user_shlink.shlink
        JOIN shlink_access on shlink_access.id=user_shlink.shlink
        WHERE
          user_shlink.user=?
          and shlink_access.active=1
        `)
      .allEntries([userId])
      .map( row => {
        return {
          id: row.shlink as string,
          url: row.manifest_url as string,
          exp: row.config_exp as number,
          key: row.encryption_key as string & { length: 43 },
          flag: row.flag as string,
          label: row.label as string,
          v: row.version as number,
          config: {
            exp: row.config_exp as number,
            passcode: row.config_passcode as string
          },
          managementToken: row.management_token as string
        } as types.HealthLinkFull
      });
    for (const shl of userPubShls) {
      shl.files = this.getSHLFileSummaries(shl.id);
    }
    return userPubShls;
  },
  async addFile(linkId: string, file: types.HealthLinkFileContent): Promise<string | undefined> {
    const hash = await crypto.subtle.digest('SHA-256', file.content);
    const hashEncoded = base64url.encode(hash);
    try {
      db.transaction(() => {
        db.query(`insert or ignore into cas_item(hash, content) values(:hashEncoded, :content)`, {
          hashEncoded,
          content: file.content,
        });
    
        db.query(
          `insert into shlink_file(shlink, content_type, content_hash) values (:linkId, :contentType, :hashEncoded)`,
          {
            linkId,
            contentType: file.contentType,
            hashEncoded,
          },
        );
      });
    } catch (e) {
      console.error(e);
      return undefined;
    }

    return hashEncoded;
  },
  async deleteFile(linkId: string, content: string) : Promise<boolean> {
    // Soft delete
    db.query(
      `delete from shlink_file where shlink = :linkId and content_hash = :content`,
      {
        linkId,
        content,
      }
    );
    // Hard delete
    // db.query(`delete from cas_item where hash = :hashEncoded and content = :content`,
    // {
    //   hashEncoded,
    //   content: file.content,
    // });
    return true;
  },
  async deleteAllFiles(linkId: string) {

    db.query(
      `delete from shlink_file where shlink = :linkId`,
      {
        linkId
      }
    );

    return true;
  },
  async addEndpoint(linkId: string, endpoint: types.HealthLinkEndpointContent): Promise<string> {
    const id = randomStringWithEntropy(32);

    let updatedEndpoint = await updateAccessToken(endpoint);
    db.query(
      `insert into shlink_endpoint(
          id, shlink, endpoint_url,
          config_key, config_client_id, config_client_secret, config_token_endpoint, config_refresh_token, refresh_time,
          access_token_response)
        values (
          :id, :linkId, :endpointUrl, :key, :clientId, :clientSecret, :tokenEndpoint, :refreshToken, :refreshTime, :accessTokenResponse
        )`,
      {
        id,
        linkId,
        endpointUrl: updatedEndpoint.endpointUrl,
        key: updatedEndpoint.config.key,
        clientId: updatedEndpoint.config.clientId,
        clientSecret: updatedEndpoint.config.clientSecret,
        tokenEndpoint: updatedEndpoint.config.tokenEndpoint,
        refreshTime: updatedEndpoint.refreshTime,
        refreshToken: updatedEndpoint.config.refreshToken,
        accessTokenResponse: JSON.stringify(updatedEndpoint.accessTokenResponse),
      },
    );

    return id;
  },
  updateEndpoint(endpoint: types.HealthLinkEndpointContent): types.HealthLinkEndpointContent {
    db.query(`update shlink_endpoint set config_refresh_token=?, refresh_time=?, access_token_response=? where id=?`, [
      endpoint.config.refreshToken,
      endpoint.refreshTime,
      JSON.stringify(endpoint.accessTokenResponse),
      endpoint.id,
    ]);
    return endpoint;
  },
  getManifestEndpointIds(linkId: string): Array<string> {
    let endpointIds = db.queryEntries<{ id: string }>(`select id from shlink_endpoint where shlink=?`, [linkId]).map((r) => r.id);
    return endpointIds;
  },
  async getEndpointContent(linkId: string, endpointId: string): Promise<types.HealthLinkEndpointContent | undefined> {
    try {
      const endpointRow = db
        .prepareQuery<
          Array<unknown>,
          {
            id: string;
            endpoint_url: string;
            config_key: string;
            config_client_id: string;
            config_client_secret: string;
            config_token_endpoint: string;
            config_refresh_token: string;
            refresh_time: string;
            access_token_response: string;
          }
        >(
          `select
          id, endpoint_url,
          config_key, config_client_id, config_client_secret, config_token_endpoint, config_refresh_token,
          refresh_time, access_token_response
        from shlink_endpoint where shlink=? and id=?`,
        )
        .oneEntry([linkId, endpointId]);
      
      let endpoint: types.HealthLinkEndpointContent = {
        id: endpointRow.id,
        endpointUrl: endpointRow.endpoint_url,
        config: {
          key: endpointRow.config_key,
          clientId: endpointRow.config_client_id,
          clientSecret: endpointRow.config_client_secret,
          refreshToken: endpointRow.config_refresh_token,
          tokenEndpoint: endpointRow.config_token_endpoint,
        },
        refreshTime: endpointRow.refresh_time,
        accessTokenResponse: JSON.parse(endpointRow.access_token_response),
      };

      if (new Date(endpoint.refreshTime!).getTime() < new Date().getTime()) {
        endpoint = await updateAccessToken(endpoint);
        DbLinks.updateEndpoint(endpoint);
      }

      return endpoint;
    } catch (e) {
      return undefined;
    }
  },
  getAllFileContentForSHL(linkId: string, embeddedLengthMax: number = Infinity): Array<types.HealthLinkFileContent> {
    const shlinkFiles = db.queryEntries<types.shlink_file>(
      `select *
      from shlink_file
      where shlink=?`,
      [linkId],
    );
    return shlinkFiles.map((e) => (this.getFileContent(linkId, e.content_hash, embeddedLengthMax)));
  },
  getFileContent(shlId: string, contentHash: string, embeddedLengthMax: number = Infinity): types.HealthLinkFileContent {
    if (embeddedLengthMax === Infinity) {
      embeddedLengthMax = 1e10000;
    }
    console.log("embeddedLengthMax", embeddedLengthMax);
    let query =`select
          content_type,
          content_hash,
          content,
          (case when length(cas_item.content) <= ${embeddedLengthMax} then cas_item.content else NULL end) as content
          from shlink_file
          join cas_item on shlink_file.content_hash=cas_item.hash
          where shlink_file.shlink=:shlId and shlink_file.content_hash=:contentHash`;
    console.log("query", query);
    const fileRow = db.queryEntries<types.cas_item>(
      query,
      { shlId, contentHash },
    );

    return {
      content: fileRow[0].content,
      hash: contentHash,
      contentType: fileRow[0].content_type as types.SHLinkManifestEntry['contentType'],
    };
  },
  getSHLFileSummaries(shlId: string | undefined): types.FileSummary[] {
    const files = db.queryEntries(
      `select * from shlink_file where shlink=?`,
      [shlId],
    );
    if (!files.length) return [];
    return files.map((f) => ({
      label: f.label,
      added: f.added_time,
      contentType: f.content_type,
      contentHash: f.content_hash,
    } as types.FileSummary));
  },
  recordAccess(shlId: string, recipient: string) {
    const q = db.prepareQuery(`insert into  shlink_access_log(shlink, recipient) values (?, ?)`);
    q.execute([shlId, recipient]);

    clientConnectionListener({
      shlId,
      recipient,
    });
  },
  recordPasscodeFailure(shlId: string) {
    // TODO: add entry to shlink_access_log for IP address and time
    // add logic around passcode failures in the last N minutes and a limit of attempts within that time.

    // const q = db.prepareQuery(
    //   `update shlink_access set passcode_failures_remaining = passcode_failures_remaining - 1 where id=?`
    // );
    // q.execute([shlId]);
  },
};
