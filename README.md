# doublecookie
Basic CSRF prevention middleware using a double submit cookie

This was designed to be drop-in middleware.  app.use(doublecookie()) accepting all the defaults, then pass locals.postCheck into your template as a hidden form field.

[See csurf first](https://github.com/expressjs/csurf)  
[owasp csrf](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet)
[Liran Tal video - Node JS: Security Breaking the Loop](https://www.youtube.com/watch?v=DX8FSC_7wRI)