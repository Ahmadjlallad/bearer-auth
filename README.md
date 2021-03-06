# bearer-auth

bearer auth training (┬┬﹏┬┬)

Links:

- [basic-auth-heroku](https://jallad-bearer-auth.herokuapp.com/)
- [readMe](https://github.com/Ahmadjlallad/bearer-auth#readme)
- [latest PR](https://github.com/Ahmadjlallad/bearer-auth/pull/1)
- [actions](https://github.com/Ahmadjlallad/bearer-auth/actions)

- problem domain description
  - As a user, I want to create a new account so that I may later login
  - As a user, I want to login to my account so that I may access protected information
  - As a user, I don't want to have to type my password every time I want to access protected information

## Documentation

![vi](./assets/7drawio.png)
`/singin` url use to login basic 64 encoded credentials
`/signup` url use to signup information in the bode
hash using bcrypt to encrypt the password
user can verify their email using jwt to generate a token

## jsDoc

```javascript
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
```
