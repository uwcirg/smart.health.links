import { oak, cors } from './deps.ts';
import { shlApiRouter } from './routers/api.ts';
const { Application, Router } = oak;
const { oakCors } = cors;
import env from './config.ts';

const app = new Application({ logErrors: false });

app.use(async (ctx, next) => {
  ctx.state.requestId = crypto.randomUUID();
  const t0 = new Date().getTime();
  await next();
  const t1 = new Date().getTime();
  const status = ctx.response.status;
  console.log(JSON.stringify({
    severity: "info",
    occurred: new Date().toISOString(),
    request_id: ctx.state.requestId,
    entity: {
      detail: {
        method: ctx.request.method,
        url: ctx.request.url.toString(),
        status: String(status),
        duration_ms: String(t1 - t0),
      }
    }
  }));
});

app.use(oakCors());

app.use(async (ctx, next) => {
  try {
    await next();
  } catch (err) {
    // Handlers that already audited this failure via handleError() set this flag
    // before throwing, so it isn't logged twice here.
    if (!ctx.state.errorHandled) {
      console.log(JSON.stringify({
        severity: "critical",
        occurred: new Date().toISOString(),
        request_id: ctx.state.requestId,
        outcome: `${err.status || 500} ${err.message || 'Internal Server Error'}`,
        entity: {
          detail: {
            method: ctx.request.method,
            url: ctx.request.url.toString(),
            error: String(err.stack || err),
          }
        }
      }));
    }

    ctx.response.status = err.status || 500;

    ctx.response.body = {
      message: err.message || 'Internal Server Error',
      details: err.details || null,
    };

    ctx.response.type = "application/json";
  }
});

const appRouter = new Router()
  .get('/', (context) => {
    context.response.body = 'Index';
  })
  .use(`/api`, shlApiRouter.routes(), shlApiRouter.allowedMethods())

app.use(appRouter.routes());
app.addEventListener('error', (evt) => {
  if (evt?.error?.toString().startsWith('Http: connection closed before message completed')) {
    // normal expected behavior after a SSE connection dies
    // See https://github.com/oakserver/oak/issues/387
    return;
  }
  console.log(JSON.stringify({
    severity: "error",
    occurred: new Date().toISOString(),
    request_id: evt.context?.state?.requestId,
    entity: {
      detail: {
        type: evt.type,
        message: String(evt.message),
        error: String(evt.error),
      }
    }
  }));
});

const port = env.PORT;
console.info('CORS-enabled web server listening on port ' + port);
app.listen({ port });
export default app;
