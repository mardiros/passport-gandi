/// should be @types/chai-passport-strategy

import chai = require("chai");
import { Strategy } from "passport-oauth2";
import { AuthenticateOptions } from "passport";
import { Request } from "express";

declare global {
  interface Test {
    success(cb: Function): Test;
    fail(cb: Function): Test;
    redirect(cb: Function): Test;
    pass(cb: Function): Test;
    error(cb: Function): Test;
    req(cb: (req: Request) => void): Test;

    authenticate(options: any): void;
  }

  interface Passport {
    use(strategy: Strategy): Test;
  }

  namespace Chai {
    interface ChaiStatic {
      passport: Passport;
    }
  }
}
export = chai;
