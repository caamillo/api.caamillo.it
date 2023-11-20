const { z } = require('zod')

module.exports = z.object({
    guest: z.boolean(),
    rcon: z.boolean(),
    name: z.string()
})