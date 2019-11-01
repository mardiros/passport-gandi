import chai, { expect } from "chai";
import "mocha";

import { Request } from "express";
import { GandiStrategy } from "./strategy";

chai.use(require("chai-passport-strategy"));

describe("Instanciate the strategy", () => {
  it("should return a Gandi strategy", () => {
    const strategy = new GandiStrategy({
      clientID: "8888",
      clientSecret: "****",
      callbackURL: "http://[::1]/callback"
    });
    expect(strategy.name).to.equal("Gandi");
  });
});

describe("Redirect to /authorize", function() {
  const strategy = new GandiStrategy({
    clientID: "8888",
    clientSecret: "****",
    callbackURL: "http://[::1]/callback"
  });
  let url = "";

  before(function(done) {
    chai.passport
      .use(strategy)
      .redirect((u: string) => {
        url = u;
        done();
      })
      .req((req: Request) => {
        if (req.session) {
          req.session.clear();
        }
      })
      .authenticate("Gandi");
  });

  it("should be redirected", function() {
    expect(url).to.equal(
      "https://id.gandi.net/authorize?" +
        "response_type=code&" +
        "redirect_uri=http%3A%2F%2F%5B%3A%3A1%5D%2Fcallback&" +
        "client_id=8888"
    );
  });
}); // authorization request with documented parameters
