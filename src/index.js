import { Elysia } from "elysia"
import { whois } from "./utils/whois";

const app = new Elysia()
  .get("/whois/:url", async ({ query: { parsed }, params: { url } }) =>
    await whois(url, parsed === 'true')
  )
  .listen(Bun.env['API_PORT']);

console.log(`api.caamillo.it is running at ${app.server?.hostname}:${app.server?.port}`)
