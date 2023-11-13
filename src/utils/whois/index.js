const { lookup } = require("whois-light")
const parser = require('./parser')

const whois = async (url, parsed=false) => {
    try {
        const res = await lookup(url)
        if (!parsed) return res
        return parser(res, url)
    } catch(err) {
        console.log(err)
    }
    return undefined
}

module.exports = {
    whois
}