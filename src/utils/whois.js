const { lookup } = require("whois-light")
const parser = require('bun-whois-parser')

module.exports = async (url, parsed=false) => {
    try {
        const res = await lookup(url)
        if (!parsed) return res
        return parser(res, url)
    } catch(err) {
        console.error(err) // Debug only
        return {
            error: 'TLD not found!',
            url: url
        }
    }
}