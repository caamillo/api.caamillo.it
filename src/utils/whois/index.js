const { lookup } = require("whois-light")
const parser = require('./parser')

const whois = async (url, parsed=false) => {
    try {
        const res = await lookup(url)
        if (!parsed) return res
        return await parser(res, url)
    } catch(err) {
        console.error(err) // Debug only
        return {
            error: 'TLD not found!',
            url: url
        }
    }
}

module.exports = {
    whois
}