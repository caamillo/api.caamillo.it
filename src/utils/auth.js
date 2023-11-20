const parseJwt = (token) =>
    JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString())
  
const canAction = async (token, service, client) => {
  const user = parseJwt(token)
  if (user.guest) {
    const grant = service.grant.find(grant => grant.name === 'guest')
    if (!grant) return false

    const results = await client.lRange(`actions:${ token }`, 0, -1)
    const actions = results.map(res => JSON.parse(res)).filter(action => action.service_id === service.id)

    const now = new Date()

    const [ how, mesure ] = grant.per

    const recentActions = actions.filter(action => {
      const diffDates = Math.abs(now - new Date(action.pushed_on))
      let diff
      switch (mesure) {
        case 'm':
            diff = diffDates / (1e3 * 60)
          break
      }
      return diff <= how
    })
    console.log(recentActions.length)

    if (recentActions.length >= grant.limit) return 2

    // Add Action
    await client.rPush(`actions:${ token }`, JSON.stringify({
      service_id: service.id,
      pushed_on: new Date().toISOString()
    }))

    return 1
  } else if (user.rcon) return 1
  return 0
}

module.exports = async (jwt) => {
    const auth = async (token, secret, UserSchema, set) => {
        try {
          if(!jwt.verify(token, secret)) {
            set.status = 401
            return false
          }
          UserSchema.parse(parseJwt(token))
          return true
        } catch (err) {
          return false
        }
    }

    return {
        auth, parseJwt, canAction
    }
}

