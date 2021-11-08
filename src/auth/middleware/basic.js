"use strict";

const base64 = require("base-64");
const { users } = require("../models/index");
/**
 *
 * @param {Request} req
 * @param {Response} res
 * @param {import("express").NextFunction} next
 * @returns {Promise<void>}
 * @description Basic Auth Middleware for Express Router Middleware
 */
module.exports = async (req, res, next) => {
  if (!req.headers.authorization) {
    return _authError();
  }
  req.headers.authorization = req.headers.authorization.split(" ").pop();
  let basic = req.headers.authorization;
  let [username, pass] = base64.decode(basic).split(":");
  try {
    req.user = await users.authenticateBasic(username, pass);
    next();
  } catch (e) {
    res.status(403).send("Invalid Login ");
  }
};
