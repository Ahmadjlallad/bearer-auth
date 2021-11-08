"use strict";

const { users } = require("../models/index.js");
/**
 *
 * @param {import("express").Request} req
 * @param {import("express").Response} res
 * @param {import("express").NextFunction} next
 * @returns {Promise<void>}
 * @description This function is used to check if the token is valid
 */
module.exports = async (req, res, next) => {
  try {
    if (!req.headers.authorization) {
      next("Invalid Login");
    }
    const token = req.headers.authorization.split(" ").pop();
    const validUser = await users.authenticateToken(token);
    req.user = validUser;
    req.token = validUser.token;
    next();
  } catch (e) {
    res.status(403).send("Invalid Login");
  }
};
