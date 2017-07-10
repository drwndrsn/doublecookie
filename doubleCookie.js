const crypto = require('crypto')
const random = require('randomatic')

/**
 * Simple middleware for doublecookie CSRF defense: 
 * 1. Sets a session cookie and puts a hash of that cookie in res.locals.postCheck 
 * on each subsequent successful request - for use in a hidden form input.
 * 2. Compares the cookie and hash on each post-like request, Err if no match
 *
 * @param {String} `secret` if you want to override randomatic 64 char string
 * @api public
 */

const doubleCookie = function (secret) {

    const middleware = function (req, res, next) {

        const hash = function (inputStr) {
            return crypto.createHash('sha256').update(inputStr).digest('hex')
        }

        const reload = function () {
            if (!req.signedCookies.dblCookie) {
                var newCookie = secret || random('*',64)
                res.cookie('dblCookie', newCookie, { signed: true, httpOnly: true })
            }
            const dblCookie = req.signedCookies.dblCookie || newCookie
            res.locals.postCheck = hash(dblCookie)
        }

        const postMethods = ['POST', 'PUT', 'PATCH', 'DELETE']
        if (postMethods.includes(req.method)) {
            if ((!req.signedCookies.dblCookie) || hash(req.signedCookies.dblCookie) !== req.body.postCheck) {
                return (next(new Error('DoubleCookie CSRF')))
            } 
        }
        reload()
        next()
    }

    return middleware

}

module.exports = doubleCookie