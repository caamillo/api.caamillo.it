import { Elysia } from "elysia"
import { whois } from "./utils/whois";

const app = new Elysia()
  .group('/v1', app =>
    app
    .get("/whois/:url", async ({ query: { parsed }, params: { url } }) =>
      await whois(url, parsed === 'true') ?? { error: 'Unexpected Error' }
    )
  )
  .listen(Bun.env['API_PORT']);

console.log(`api.caamillo.it is running at ${ app.server?.hostname }:${ app.server?.port }`)
