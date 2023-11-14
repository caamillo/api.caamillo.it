import { Elysia } from "elysia"
import jwt from 'jsonwebtoken'
import { bearer } from '@elysiajs/bearer'
const path = require('path')

import whois from "./utils/whois"

const JWT_EXPIRE_IN = '1d'

const auth = (token, set) => {
  try {
    if(!jwt.verify(token, Bun.env['SECRET_KEY'])) {
      set.status = 401
      return false
    }
    return true
  } catch (err) {
    return false
  }
}

const app = new Elysia()
  .use(bearer())
  .get('/', () => Bun.file(path.join(import.meta.path, '../views/index.html')))
  .post('/token', async ({ body: { name, pw }, set }) => {
    if (!name || typeof name !== 'string' || !pw || typeof pw !== 'string') {
      set.status = 400
      return 'Bad request'
    }
    if (pw !== Bun.env['SECRET_PW']) {
      set.status = 401
      return 'Unauthorized'
    }
    const accessToken = await jwt.sign({
      name: name
    }, Bun.env['SECRET_KEY'], { expiresIn: JWT_EXPIRE_IN }) // 1 day
    return accessToken
  })
  .group('/v1', app => {
    app.onBeforeHandle(({ bearer, set }) => {
      if (!auth(bearer, set)) return Bun.file(path.join(import.meta.path, '../views/index.html'))
    })
    return app
      .get("/whois/:url", async ({ query: { parsed }, params: { url } }) =>
        await whois(url, parsed === 'true') ?? { error: 'Unexpected Error' }
      )
  })
  .get('/*', () => Bun.file(path.join(import.meta.path, '../views/404.html')))
  .listen(Bun.env['API_PORT']);

console.log(`api.caamillo.it is running at ${ app.server?.hostname }:${ app.server?.port }`)