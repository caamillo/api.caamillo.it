# api.caamillo.it

## What's this?

> Some shit api for some shit service

Basically an api handler using:
- [Bun](https://bun.sh/) as runtime,
- [ElysiaJS](https://elysiajs.com/) as web framework,
- [JWT](https://jwt.io/) as auth-handler,
- [Redis](https://redis.io/) as cached-memory storage 

for [caamillo.it](https://caamillo.it) services.

## Services

- Whois API (raw or [parsed](https://github.com/caamillo/bun-whois-parser)) `/v1/whois/{ URL }?parsed={ true || false }`
  
## How it works
if you see `.env.example` there is `SECRET_KEY` that needs JWT for authentication. But wait, since I don't really need a db, you can login with two pws: one for guest and rcon only for administration/debugging purpose. So when you make POST req in `/token` with `name` and `pw` in a JSON body you'll gave the access-token that you need for your reqs. However, you can limit guest access by service (check `services.json`). The anti-flood system is written using Redis cache-storage and prevent it using your IP address (I know that this may be not the best practice but fuck it I only need this for a stupid showcase).


## TODOs

- [ ] Write some logic to flush redis cache when jwt token expired (maybe directly add EXPIRE attribute to `actions:{ IP }` key)
- [ ] Add more API to user management (give user last `pushed_on` of given `service_id`)
