"use strict";

const middleware = require("../../../src/auth/middleware/basic");
const { db, users } = require("../../../src/auth/models/index");

let userInfo = {
  admin: { username: "admin", password: "password" },
};

describe("Auth Middleware", () => {
  // admin:password: YWRtaW46cGFzc3dvcmQ=
  // admin:foo: YWRtaW46Zm9v

  // Mock the express req/res/next that we need for each middleware call
  const req = {};
  const res = {
    status: jest.fn(() => res),
    send: jest.fn(() => res),
  };
  const next = jest.fn();

  describe("user authentication", () => {
    it("fails a login for a user (admin) with the incorrect basic credentials", () => {
      beforeAll(async (done) => {
        await db.sync();
        await users.create(userInfo.admin);
        done();
      });
      afterAll(async (done) => {
        await db.drop();
        done();
      });
      // Change the request to match this test case
      req.headers = {
        authorization: "Basic YWRtaW46Zm9v",
      };

      return middleware(req, res, next).then(() => {
        console.log(
          "---------------------------------------------------------------------------------------"
        );
        console.log(res.status);
        expect(next).not.toHaveBeenCalled();
        expect(res.status.mock.calls.flat(5)).toHaveBeenCalledWith(403);
        console.log(res.status.mock.calls);
      });
    }); // it()

    it("logs in an admin user with the right credentials", () => {
      // Change the request to match this test case
      req.headers = {
        authorization: "Basic YWRtaW46cGFzc3dvcmQ=",
      };

      return middleware(req, res, next).then(() => {
        expect(next).toHaveBeenCalledWith();
      });
    }); // it()
  });
});
