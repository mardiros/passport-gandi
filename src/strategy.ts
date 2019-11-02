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

/** Strategy option to provide. */
export interface StrategyOptions {
  /** Client ID To Provide.
   *
   * retrieve when registering your application. */
  clientID: string;
  /** Client Secret To Provide.
   *
   * retrieve when registering your application. */
  clientSecret: string;
  /** OAuth2.0 Callback URL
   *
   * This URL must be registered at Gandi. */
  callbackURL: string;

  /** Optional parameter to implement OAuth2.0 state */
  store?: StateStore;
  /** Optional parameter to implement OAuth2.0 state */
  state?: any;

  /** Restrict your application to this scope.
   *
   * The scopes are set on your application registration,
   * and here is a subset only of the scope. You should not use it,
   * instead, keep the list of scope in your registred application.
   */
  scope?: string | string[];
  /** Used to override Gandi OAuth2 /authorized URL for testing purpose. */
  authorizationURL?: string;
  /** Used to override Gandi OAuth2 /token URL for testing purpose. */
  tokenURL?: string;
  /** Used to override Gandi OAuth2 /tokeninfo URL for testing purpose. */
  tokenInfoURL?: string;

  // scopeSeparator?: string;
  // sessionKey?: string;
}

/** Function used to get the get the expiration date of the access token.
 * The number return is a timestamp in milliseconds.
 */
const getExpiresAt = (expiresIn: number): number => {
  const expiresAt = new Date();
  const expiresDrift = expiresIn - 30; // 30 seconds drift
  expiresAt.setSeconds(expiresAt.getSeconds() + expiresDrift);
  return expiresAt.getTime();
};

/**
 * Format of the /tokeninfo json body return.
 * It will be used to build the profile info of passport.
 */
export interface IProfileInfo {
  /** identifier of the authenticated user. imutable field. */
  user_id: string;
  /**
   * username of the authenticated user, required the `account:public`
   * scope on the registered app.
   */
  username?: string; // you must have  scope to get it defined
  /**
   * lang of the authenticated user, required the `account:public`
   * scope on the registered app.
   */
  lang: string;
  /**
   * number of second when the access token will expires.
   */
  expires_in: number; // tslint: allow-snake-case
}

/**
 * Serialized tokens format (stored in express session).
 */
interface ITokens {
  accessToken: string;
  refreshToken: string;
  expiresAt: number;
}

export class Tokens implements ITokens {
  /**
   * Create the token object from POJO that implement IToken.
   * @param obj the POJO object
   */
  public static from_object(obj: ITokens): Tokens {
    return new Tokens(obj.accessToken, obj.refreshToken, obj.expiresAt);
  }
  /**
   * Create the token from the profile, just after an OAuth2.0 dance.
   * @param profile User Profile Information
   * @param accessToken OAuth2.0 access token
   * @param refreshToken OAuth2.0 refresh token
   */
  public static from_profile(
    profile: IProfileInfo,
    accessToken: string,
    refreshToken: string
  ): Tokens {
    const expiresAt = getExpiresAt(profile.expires_in);
    return new Tokens(accessToken, refreshToken, expiresAt);
  }

  /**
   * Create tokens from a refresh token, when the access token has expired.
   *
   * The method [[Tokens.save]] has to be called to keep new access token in
   * the session.
   * @param refreshToken OAuth2.0 Refresh token to consume
   * @param options OAuth2.0 configuration
   */
  public static async from_refresh_token(
    refreshToken: string,
    options: StrategyOptions
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

  /**
   * Create the Token object, use static methods instead:
   *  - [[Token.from_object]] to load from the session.
   *  - [[Token.from_profile]] to load after oauth2.0 dance (Authorication Code).
   *  - [[Token.from_refresh_token]] to load after the access token has expired.
   *
   * @param accessToken OAuth2.0 access token
   * @param refreshToken OAuth2.0 refresh token
   * @param expiresAt Expiration date of the access token (timestamp)
   */
  constructor(accessToken: string, refreshToken: string, expiresAt: number) {
    this.accessToken = accessToken;
    this.refreshToken = refreshToken;
    this.expiresAt = expiresAt;
  }
  /**
   * Serialize Tokens and save it the session.
   */
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

  /** Check if the access token is dead or alive. */
  public hasExpired = () => {
    const date = new Date(this.expiresAt);
    const now = new Date();
    return now > date;
  };
}

/** Callback function to retrieve the profile info after the OAuth2.0 dance */
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
        .get<IProfileInfo>(options.tokenInfoURL || defaultTokenInfoURL)
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

/**
 * Passport Strategy for Gandi OAuth2.0.
 */
export class GandiStrategy extends OAuth2Strategy {
  /**
   * Parameters to configure a register application at Gandi.
   * @param options configuration to use
   */
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
      passReqToCallback: true
    };
    super(oauth2opts, tokenToProfile(options));
    this.name = "Gandi";
  }
}
