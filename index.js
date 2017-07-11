const crypto = require('crypto')
const random = require('randomatic')

/**
 * Simple middleware for double request cookie CSRF defense: 
 * 1. Sets a session cookie and puts a hash of that cookie in res.locals.postCheck 
 * for use in a hidden form input.
 * 2. Compares the cookie and hash on each post-like request, Err if no match
 *
 * @param {object} cfg Configuration object
 * @param {bool} cfg.always Set True to refresh cookie on each request
 * @api public
 */

const doubleCookie = function (cfg) {

    cfg = cfg || {}
    cfg.always = cfg.always || false

    const middleware = function (req, res, next) {

        // Utility function
        const hash = function (inputStr) {
            return crypto.createHash('sha256').update(inputStr).digest('hex')
        }

        // Kill bad requests
        const postMethods = ['POST', 'PUT', 'PATCH', 'DELETE']
        if (postMethods.includes(req.method)) {
            // If there's no cookie or the cookie doesn't match its hash
            if ((!req.signedCookies.dblCookie) || hash(req.signedCookies.dblCookie) !== req.body.postCheck) {
                return (next(new Error('DoubleCookie CSRF')))
            } 
        }

        const reload = function () {
            // If either there's no dblCookie or cfg says to always reload, reload
            if (!req.signedCookies.dblCookie || cfg.always) {
                var newCookie = random('*',64)
                res.cookie('dblCookie', newCookie, { signed: true, httpOnly: true })
            }
            const dblCookie = newCookie || req.signedCookies.dblCookie
            res.locals.postCheck = hash(dblCookie)
        }

        // GET or legit POST
        reload()
        next()

    }

    return middleware

}

module.exports = doubleCookie