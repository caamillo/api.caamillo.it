const patterns = require('./patterns')

const sanify = (parsed, etc) => {
	Object.keys(parsed).map(key => {
		let value = parsed[key]
		value = value?.trim()
		value = value?.length ? value : undefined
		parsed[key] = value
	})
	return parsed
}

const parse = (data, { regex, etc }) => {
	const parsed = {}
	Object.keys(regex).map(key => {
		const match = data.match(regex[key])?.slice(-1)?.join()
		parsed[key] = match
	})
	// TODO format dates
	return sanify(parsed)
}

module.exports = (data, url) => {
	const tld = url.split('.').slice(-1).join() // wrap TLD
	let pattern = patterns.find(el => el.tld === tld)
	pattern = pattern ? {
		regex: {
			...patterns[0].regex,
			...pattern.regex
		},
		etc: {
			...patterns[0].etc,
			...pattern.etc
		}
	} : patterns[0]
	const parsed = parse(data, pattern)
	return parsed
}