# passport-gandi

Gandi Authentication strategy for [Passport](http://passportjs.org/).

This module use Gandi OAuth 2.0 Authorization Server in your Node.js
applications to consume the [Gandi API](https://api.gandi.net/docs/).

Note that it currently only support [Express](http://expressjs.com/)
and require a session that has been initialized first.

## Usage (in typescript)

```ts
import bodyParser from "body-parser";
import cookieSession from "cookie-session";

import { Application, Request, Response } from "express";
import { AxiosError, AxiosResponse, Method } from "axios";

import passport from "passport";
import { GandiStrategry, IProfileInfo } from "passport-gandi";

const OAUTH2_CONFIG = {
  clientID: "<Your client id>",
  clientSecret: "<Your client secret>",
  callbackURL: "https://<Your Hostname>/auth/callback"
};

// Create the applicaiton
const app: Application = express();

// Express does not handle a raw body version for us :-/
// https://stackoverflow.com/questions/9920208/expressjs-raw-body/13565786
app.use(bodyParser.json());

// Initialize a session,
// FIXME: for security reason, tokens must stay innaccessible to the end user.
// Otherwise he can leak the identity of the registered application.
// See: https://github.com/expressjs/cookie-session/issues/9
app.use(
  cookieSession({
    secret: "secret-that-sign-the-cookie",
    secure: true
  })
);

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user: IProfileInfo, cb) => {
  // you might store things here with the "user" from your database
  // user.user_id is a string (uuid format)
  cb(null, user);
});

passport.deserializeUser((obj, cb) => {
  // you might store things here with the "user" from your database
  cb(null, obj);
});

const strategy = new OAuth2Strategy(OAUTH2_CONFIG);
passport.use(strategy);

app.get("/auth/error", (req: Request, res: Response) => {
  // the query string of the request contains error and error_description
  // for the explanation.
  // See https://tools.ietf.org/html/rfc6749#section-4.1.2.1
  res.send("Login failed!");
});

app.get(
  "/auth/callback",
  passport.authenticate("Gandi", { failureRedirect: "/auth/error" }),
  (req, res) => {
    console.log("Successful authentication, redirect to authenticated page");
    res.redirect("/");
  }
);

/**
 * Express middleware to authenticate at Gandi, in case it has no tokens.
 */
const authenticateUser = (req: Request, res: Response, next: NextFunction) => {
  const token = req.session && req.session.tokens;
  if (!token) {
    res.redirect("/auth/callback");
    return;
  }
  next();
};

/**
 * Express middleware to keep the access token alive.
 */
const ensureAccessToken = (req: Request, res: Response, next: NextFunction) => {
  const ensureAccessTokenImpl = async (req: Request) => {
    if (req.session) {
      let tokens: Tokens = Tokens.from_object(req.session.tokens);
      if (tokens.hasExpired()) {
        // refresh token here
        console.log("Token has expired, refresh them");
        tokens = await Tokens.from_refresh_token(
          tokens.refreshToken,
          req.session
        );
        tokens.save(req.session);
      }
    }
  };
  ensureAccessTokenImpl(req).then(() => next());
};

/**
 * HTTP Client that contains the bearer token
 */
const getHttpClient = (req: Request) => {
  const token = req.session && req.session.tokens.accessToken;
  return axios.create({
    timeout: 15 * 1000,
    headers: {
      common: {
        Authorization: token && `Bearer ${token}`
      }
    }
  });
};

/**
 * Proxy HTTP Call to Gandi API with the correct credentials (access token).
 */
const callApi = (req: Request, res: Response) => {
  const path = req.params[0];
  let url = `https://api.gandi.net/${path}`;
  const method = req.method as Method;
  const headers = req.headers;
  const data = req.body;
  if (req.query) {
    url += `?${qs.stringify(req.query)}`;
  }

  console.log(`${method}, ${url}, ${headers}, ${data}`);

  const promResp = getHttpClient(req).request({ method, url, headers, data });
  promResp
    .then((resp: AxiosResponse<string>) => {
      return proxyResp(res, resp);
    })
    .catch((err: AxiosError<any>) => {
      if (err.response) {
        proxyResp(res, err.response);
      } else {
        console.log(err);
        res.send("Something wrong happen...");
      }
    });
}

// we ensure the user is authenticated and has a valid token before performing
// the call.
app.all(
  "/api/*",
  authenticateUser,
  ensureAccessToken,
  callApi
);

// A view that ensure the user is authenticated before rendering.
app.get("/*", authenticateUser, (req: Request, res: Response) => {
  let username = req.user && req.user["username"];
  res.send(`Hello ${username}!`);
});
```
