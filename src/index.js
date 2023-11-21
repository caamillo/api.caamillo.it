import { Elysia } from "elysia"
import jwt from 'jsonwebtoken'
import { bearer } from '@elysiajs/bearer'
import { ip } from "elysia-ip"
import { createClient } from 'redis'
const path = require('path')

import whois from "./utils/whois"

const JWT_EXPIRE_IN = '1d'

;(async () => {
  // Services
  const services = JSON.parse(await (Bun.file(path.join(import.meta.path, '../../services.json'), { type: 'application/json' })).text())

  // Schemas
  const UserSchema = require('./schemas/User')

  // Utils
  const { auth, parseJwt, canAction } = await require('./utils/auth')(jwt)

  // Redis client
  const client = createClient()
  client.on('error', err => console.error('Redis Client Error', err))

  await client.connect()

  // App Router
  const app = new Elysia()
    .use(bearer())
    .use(ip())
    .get('/', () => Bun.file(path.join(import.meta.path, '../views/index.html')))
    .post('/token', async ({ body: { name, pw }, set }) => {
      if (!name || typeof name !== 'string' || !pw || typeof pw !== 'string') {
        set.status = 400
        return 'Bad request'
      }

      const identity = {
        rcon: pw === Bun.env['SECRET_RCON_PW'],
        guest: pw === Bun.env['SECRET_GUEST_PW'],
        name: name
      }

      if (!identity.rcon && !identity.guest) {
        set.status = 401
        return 'Unauthorized'
      }

      const accessToken = await jwt.sign(identity, Bun.env['SECRET_KEY'], { expiresIn: JWT_EXPIRE_IN }) // 1 day
      
      return accessToken
    })
    .group('/v1', app => {
      app.onBeforeHandle(async ({ bearer, set, request, ip }) => {
        console.log('ip2', ip)
        if (!await auth(bearer, Bun.env['SECRET_KEY'], UserSchema, set)) return Bun.file(path.join(import.meta.path, '../views/401.html'))
      })
      
      for (let service of services) {
        app.group(`/${ service.name }`, app => {
          app.onBeforeHandle(async ({ bearer, ip }) => {
            console.log('ip1', ip)
            const result = await canAction(bearer, service, client, ip)
            switch (result) {
              case 0:
                return Bun.file(path.join(import.meta.path, '../views/401.html'))
              case 1:
                return undefined
              case 2:
                return { error: 'Too many requests!', message: 'Please wait to regain access to this route' }
            }
          })
          
          return app.get("/:url", async ({ query: { parsed }, params: { url } }) =>
            await whois(url, parsed === 'true') ?? { error: 'Unexpected Error' }
          )
        })
      }

      return app
    })
    .get('/*', () => Bun.file(path.join(import.meta.path, '../views/404.html')))
    .listen(Bun.env['API_PORT']);

  console.log(`api.caamillo.it is running at ${ app.server?.hostname }:${ app.server?.port }`)
})()