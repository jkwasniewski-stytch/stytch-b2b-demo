# Overview

Bake your favorite desert to get roles and *rise* the leaderboard.

https://bake.kwasniewski.me/

This is the silly project to test out stytch b2b features.

Frontend via vite pushed to github pages.

Backend via cloudflare worker and typescript.

There are a few rules in cloudflare to make the frontend fully work.

```
URI Full wildcard r"https://bake.kwasniewski.me/authenticate*" - > Rewrite path to wildcard_replace
URI Full wildcard r"https://bake.kwasniewski.me/dashboard*" - > Rewrite path to wildcard_replace
```

