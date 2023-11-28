const ms = require('ms')

const parseJwt = (token) =>
    JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString())

const ActionResponse = (code=0, data='', remaining=-1) => {
  return {
    code: code,
    data: data,
    remaining: remaining
  }
}
  
const canAction = async (token, service, client, ip, DEBUG_INFO) => {
  const user = parseJwt(token)
  ip = typeof ip === 'string' ? ip : '127.0.0.1'
  if (DEBUG_INFO) console.log('[ DEBUG ] ip address:', ip)
  if (user.guest) {
    const grant = service.grant.find(grant => grant.name === 'guest')
    if (!grant) return ActionResponse(0, 'Not Authorized')

    const results = await client.lRange(`actions:${ ip }`, 0, -1)
    const actions = results.map(res => JSON.parse(res)).filter(action => action.service_id === service.id)

    const now = new Date()

    const recentActions = actions.filter(action =>
      now - new Date(action.pushed_on) <= ms(grant.per)  
    )

    actions.map(async action => {
      if (recentActions.filter(recentAction => recentAction.pushed_on === action.pushed_on).length > 0) return
      // console.log('[ DEBUG ] deleting ', action)
      await client.lRem(`actions:${ ip }`, 0, JSON.stringify(action))
    })

    if (DEBUG_INFO) console.log('[ DEBUG ] actions by ip:', recentActions.length + 1)

    if (recentActions.length >= grant.limit) return ActionResponse(2, 'Too Many Reqs!', 0)

    // Add Action
    await client.rPush(`actions:${ ip }`, JSON.stringify({
      service_id: service.id,
      pushed_on: new Date().toISOString()
    }))

    return ActionResponse(1, 'Action has been dispatched successfully', grant.limit - recentActions.length - 1)
  } else if (user.rcon) return ActionResponse(1, 'Action has been dispatched successfully', -1)
  return ActionResponse(0, 'Action has been dispatched successfully')
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

