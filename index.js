const crypto = require('crypto')
const random = require('randomatic')

/**
 * Simple middleware for double request cookie CSRF defense: 
 * 1. Sets a session cookie and puts a hash of that cookie in res.locals.postCheck 
 * for use in a hidden form input.
 * 2. Compares the cookie and hash on each post-like request, Err if no match
 *
 * @param {object} options Configuration object
 * @param {bool} options.always Default false.  Set true to refresh cookie on each request, but this'll break back button.
 * @param {bool} options.secure Default true.  You should always use https in production.  False ok for development
 * @param {bool} options.httpOnly Default true. Flags the cookie to be accessible only by the web server
 * @param {bool} options.signed Default true.  Requires a signature from cookie-parser.  Load that middleware first.
 * @api public
 */

const doubleCookie = function (options) {

    let {
        always = false,
        secure = true,
        httpOnly = true,
        signed = true
    } = options

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
                console.log("double", req.signedCookies.dblCookie)
                return (next(new Error('DoubleCookie CSRF')))
            } 
        }

        const reload = function () {
            // If either there's no dblCookie yet or options says to always refresh, reload
            if (!req.signedCookies.dblCookie || always) {
                var newCookie = random('*',64)
                res.cookie('dblCookie', newCookie, { signed: signed, httpOnly: httpOnly, secure: secure })
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