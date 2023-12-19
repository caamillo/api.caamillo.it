import { Elysia } from "elysia"
import jwt from 'jsonwebtoken'
import { bearer } from '@elysiajs/bearer'
import { ip } from "elysia-ip-caamillo"
import { createClient } from 'redis'
import { cors } from '@elysiajs/cors'
import ms from 'ms'
const path = require('path')

import whois from "./utils/whois"

const { UnexpectedError, TooManyReqs, NotAuthorized } = require('./utils/error')

const JWT_EXPIRE_IN = '1d'

;(async () => {
  // Services
  const services = JSON.parse(await (Bun.file(path.join(import.meta.path, '../../services.json'), { type: 'application/json' })).text())
  const domains = JSON.parse(await (Bun.file(path.join(import.meta.path, '../../domains.json'), { type: 'application/json' })).text())

  // Schemas
  const UserSchema = require('./schemas/User')

  // Utils
  const { auth, parseJwt, canAction, logout } = require('./utils/auth')

  const DEBUG_INFO = Bun.env['DEBUG_INFO'] ? Bun.env['DEBUG_INFO'] === 'TRUE' : false

  // Redis client
  const client = createClient()
  client.on('error', err => console.error('Redis Client Error', err))

  await client.connect()

  // App Router
  const app = new Elysia()
    .use(bearer())
    .use(ip({
      sanitize: (ip) => ip = typeof ip === 'string' ? ip : '127.0.0.1'
    }))
    .use(cors())
    .get('/', () => Bun.file(path.join(import.meta.path, '../views/index.html')))
    .post('/token', async ({ body: { name, pw }, set, ip }) => {
      if (!name || typeof name !== 'string' || !pw || typeof pw !== 'string') {
        set.status = 400
        return 'Bad request'
      }

      const identity = {
        rcon: pw === Bun.env['SECRET_RCON_PW'],
        guest: pw === Bun.env['SECRET_GUEST_PW'],
        name: name,
        expires: new Date(Date.now() + ms(JWT_EXPIRE_IN)).toISOString()
      }

      if (!identity.rcon && !identity.guest) return NotAuthorized(set)

      // Check if user is already logged
      const usr = await client.get(`login:${ ip }`)
      if (usr && jwt.verify(usr, Bun.env['SECRET_KEY'], (err) => !err)) {
        if (DEBUG_INFO) console.log(`[ DEBUG ] user ${ ip } was already logged:`, usr)
        return {
          title: 'forward',
          data: usr
        }
      }

      if (DEBUG_INFO) console.log(`[ DEBUG ] user ${ ip } identity:`, identity)

      const accessToken = await jwt.sign(identity, Bun.env['SECRET_KEY'], { expiresIn: JWT_EXPIRE_IN }) // 1 day

      // Creating expire
      await client.set(`login:${ ip }`, accessToken, `PX ${ ms(JWT_EXPIRE_IN) }`) // Expiring Login Info
      await client.rPush(`actions:${ ip }`, '')
      await client.expire(`actions:${ ip }`, ms(JWT_EXPIRE_IN) * 1e3) // Expiring Actions
      
      return {
        title: 'success',
        data: accessToken
      }
    })
    .get('/validate-token', async ({ bearer, set, ip }) =>
      await auth(jwt, bearer, Bun.env['SECRET_KEY'], UserSchema, set, client, ip) ?
        { title: 'Valid', message: 'You are authenticated', data: true } :
        { title: 'Invalid', message: 'You are not authenticated', data: false }
    )
    .get('/logout', async ({ query: { t }, ip, set }) => {
      if (await logout(jwt, t, Bun.env['SECRET_KEY'], UserSchema, set, client, ip)) return {
        title: 'Success',
        message: 'You successfully logged out'
      }

      return {
        error: 'Error',
        message: 'An error has occurred logging you out'
      }
    })
    .group('/v1', app => {
      app.onBeforeHandle(async ({ bearer, set, request, ip }) => {
        if (!await auth(jwt, bearer, Bun.env['SECRET_KEY'], UserSchema, set, client, ip)) return NotAuthorized(set)
      })
      
      for (let service of services) {
        app.group(`/${ service.id }`, app => {
          let canActionRes
          app.onBeforeHandle(async ({ bearer, ip, set }) => {
            canActionRes = await canAction(bearer, service, client, ip, DEBUG_INFO)
            if (DEBUG_INFO) console.log('[ DEBUG ] canActionRes:', canActionRes)
            switch (canActionRes.code) {
              case 0:
                return NotAuthorized(set)
              case 1:
                return undefined
              case 2:
                return TooManyReqs(set)
              default:
                return UnexpectedError(set)
            }
          })
          
          switch (service.id) {
            case 'whois':
              return app.get("/:url", async ({ query: { parsed }, params: { url }, set }) =>
                await whois(url, parsed === 'true') ?? UnexpectedError(set)
              )
            case 'bulk-whois':
              return app.get("/:name", async ({ query: { category="popular" }, params: { name }, set }) => {
                return category
              })
          }
        })
      }

      return app
    })
    .get('/*', () => Bun.file(path.join(import.meta.path, '../views/404.html')))
    .listen(Bun.env['API_PORT']);

  console.log(`api.caamillo.it is running at ${ app.server?.hostname }:${ app.server?.port }`)
})()