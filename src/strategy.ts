import axios, { AxiosResponse } from "axios";
import qs from "querystring";

import OAuth2Strategy, {
  StateStore,
  StrategyOptionsWithRequest
} from "passport-oauth2";

import { Request } from "express";

// URLs Of Gandi ID: the oauth 2.0 server
const defaultTokenInfoURL = "https://id.gandi.net/tokeninfo";
const defaultAuthorizationURL = "https://id.gandi.net/authorize";
const defaultTokenURL = "https://id.gandi.net/token";

interface StrategyOptions {
  clientID: string;
  clientSecret: string;
  callbackURL: string;
  store?: StateStore;
  state?: any;
  scope?: string | string[];
  scopeSeparator?: string;
  sessionKey?: string;
  authorizationURL?: string;
  tokenURL?: string;
  tokenInfoUrl?: string;
}

const getExpiresAt = (expiresIn: number) => {
  const expiresAt = new Date();
  const expiresDrift = expiresIn - 30; // 30 seconds drift
  expiresAt.setSeconds(expiresAt.getSeconds() + expiresDrift);
  return expiresAt.getTime();
};

export interface IProfileInfo {
  user_id: string;
  username?: string; // you must have account:public scope to get it defined
  email: string;
  expires_in: number; // tslint: allow-snake-case
}

interface ITokens {
  accessToken: string;
  refreshToken: string;
  expiresAt: number;
}

class Tokens implements ITokens {
  public static from_object(obj: ITokens) {
    return new Tokens(obj.accessToken, obj.refreshToken, obj.expiresAt);
  }
  public static from_profile(
    profile: IProfileInfo,
    accessToken: string,
    refreshToken: string
  ) {
    const expiresAt = getExpiresAt(profile.expires_in);
    return new Tokens(accessToken, refreshToken, expiresAt);
  }

  public static async from_refresh_token(
    refreshToken: string,
    options: StrategyOptions,
    session: Express.Session
  ) {
    const client = axios.create({
      timeout: 15 * 1000,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      }
    });
    let nfo = null;
    try {
      // console.log("Refreshing tokens");
      nfo = await client
        .post(
          options.tokenURL || defaultTokenURL,
          qs.stringify({
            refresh_token: refreshToken,
            grant_type: "refresh_token",
            client_id: options.clientID,
            client_secret: options.clientSecret
          })
        )
        .then(resp => resp.data);
      const expiresAt = getExpiresAt(nfo.expires_in);
      return new Tokens(nfo.access_token, nfo.refresh_token, expiresAt);
    } catch (error) {
      // console.log(`Error ${error} while refreshing tokens`);
      throw error;
    }
  }

  public accessToken: string;
  public refreshToken: string;
  public expiresAt: number;

  constructor(accessToken: string, refreshToken: string, expiresAt: number) {
    this.accessToken = accessToken;
    this.refreshToken = refreshToken;
    this.expiresAt = expiresAt;
  }

  public save = (session: Express.Session) => {
    session.tokens = this as ITokens;
    session.save((err: any) => {
      if (err) {
        // console.log(`Error ${err} while saving the session`);
      } else {
        // console.log("Credentials saved in the session");
      }
    });
  };
  public hasExpired = () => {
    const date = new Date(this.expiresAt);
    const now = new Date();
    return now > date;
  };
}

const tokenToProfile = (options: StrategyOptions) => {
  const tokenToProfileImpl = async (
    req: Request,
    accessToken: string,
    refreshToken: string,
    profile: any,
    verified: OAuth2Strategy.VerifyCallback
  ) => {
    if (!req.session) {
      // console.log("No session, we will have problem");
      const error = Error("request.session must be initialized first");
      return verified(error, undefined);
    }

    const client = axios.create({
      timeout: 15 * 1000,
      headers: {
        common: {
          Authorization: `Bearer ${accessToken}`
        }
      }
    });
    let nfo = null;
    try {
      nfo = await client
        .get<IProfileInfo>(options.tokenInfoUrl || defaultTokenInfoURL)
        .then((resp: AxiosResponse<IProfileInfo>) => resp.data);
      // console.log("Token Info: " + JSON.stringify(nfo));
    } catch (error) {
      // console.log(`Error ${error} while fetching tokeninfo`);
      return verified(error, undefined);
    }

    const tokens = Tokens.from_profile(nfo, accessToken, refreshToken);
    tokens.save(req.session);
    return verified(null, nfo);
  };

  return tokenToProfileImpl;
};


class GandiStrategy extends OAuth2Strategy {

  constructor(options: StrategyOptions) {
    let oauth2opts: StrategyOptionsWithRequest = {
      clientID: options.clientID,
      clientSecret: options.clientSecret,
      callbackURL: options.callbackURL,
      authorizationURL: options.authorizationURL || defaultAuthorizationURL,
      tokenURL: options.tokenURL || defaultTokenURL,
      store: options.store,
      state: options.state,
      scope: options.scope,
      scopeSeparator: options.scopeSeparator,
      sessionKey: options.sessionKey,
      passReqToCallback: true
    };
    super(oauth2opts, tokenToProfile(options));
    this.name = "Gandi"
  }
  
}

export { GandiStrategy };
