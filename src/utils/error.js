const DefaultError = (title="Error", message="Uff.. something went wrong", set, status=400) => {
    set?.status = status
    return {
        error: title,
        message: message
    }
}

module.exports = {
    UnexpectedError: (set, title="Unexpected Error", message, status=500) =>
        DefaultError(title, message, set, status),
    TooManyReqs: (set, title="Too many Requests", message="Please wait in order to regain access to this route", status=429) =>
        DefaultError(title, message, set, status),
    NotAuthorized: (set, title="Not Authorized", message="You are not authorized", status=401) =>
        DefaultError(title, message, set, status)
}