"use strict";

const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
/**
 *
 * @param {sequelize} sequelize
 * @param DataTypes DataTypes
 * @returns UserModel
 * @description User Model use to save and create a user in the database
 * @memberof module:models
 * @requires bcrypt
 * @requires jsonwebtoken
 * @method authenticateBasic
 * @method authenticateToken
 */
const userSchema = (sequelize, DataTypes) => {
  /**
   * @module userModel
   * @property username {String}
   * @property password {String}
   * @property token jwt token
   */
  const model = sequelize.define("User", {
    username: { type: DataTypes.STRING, allowNull: false, unique: true },
    password: { type: DataTypes.STRING, allowNull: false },
    token: {
      type: DataTypes.VIRTUAL,
      get() {
        return jwt.sign({ username: this.username }, process.env.SECRET);
      },
    },
  });
  /**
   * @method beforeCreate
   * hook to hash the password before saving the user
   * @param {object} options
   * run before saving the user at the database
   */
  model.beforeCreate(async (user) => {
    let hashedPass = await bcrypt.hash(user.password, 10);
    user.password = hashedPass;
  });

  /**
   * Users Model @method authenticateBasic
   * @param {string} username
   * @param {string} password
   * username and password are required
   * use to validate user credentials and return a user object
   */
  // Basic AUTH: Validating strings (username, password)
  model.authenticateBasic = async function (username, password) {
    const user = await this.findOne({ where: { username } });
    console.log(username, password, user);
    const valid = await bcrypt.compare(password, user.password);

    if (valid) {
      return user;
    }
    throw new Error("Invalid User");
  };
  /**
   * Users Model @method authenticateToken
   * @param {jwt} token
   * use to validate user credentials and return a user object if token is valid and not expired
   */
  // Bearer AUTH: Validating a token
  model.authenticateToken = async function (token) {
    try {
      const parsedToken = jwt.verify(token, process.env.SECRET);
      const user = await this.findOne({
        where: { username: parsedToken.username },
      });
      if (user) {
        return user;
      }
      throw new Error("User Not Found");
    } catch (e) {
      throw new Error(e.message);
    }
  };

  return model;
};

module.exports = userSchema;
