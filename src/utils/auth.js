const parseJwt = (token) =>
    JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString())
  
const canAction = async (token, service, client, ip) => {
  const user = parseJwt(token)
  ip = typeof ip === 'string' ? ip : '127.0.0.1'
  console.log('[ DEBUG ] ip address:', ip)
  if (user.guest) {
    const grant = service.grant.find(grant => grant.name === 'guest')
    if (!grant) return false

    const results = await client.lRange(`actions:${ ip }`, 0, -1)
    const actions = results.map(res => JSON.parse(res)).filter(action => action.service_id === service.id)

    const now = new Date()

    const [ unit, mesure ] = grant.per

    const recentActions = actions.filter(action => {
      const diffDates = Math.abs(now - new Date(action.pushed_on))
      let diff
      switch (mesure) {
        case 'm':
            diff = diffDates / (1e3 * 60)
          break
      }
      return diff <= unit
    })

    actions.map(async action => {
      if (recentActions.filter(recentAction => recentAction.pushed_on === action.pushed_on).length > 0) return
      // console.log('[ DEBUG ] deleting ', action)
      await client.lRem(`actions:${ ip }`, 0, JSON.stringify(action))
    })

    console.log('[ DEBUG ] actions by ip:', recentActions.length + 1)

    if (recentActions.length >= grant.limit) return 2

    // Add Action
    await client.rPush(`actions:${ ip }`, JSON.stringify({
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

