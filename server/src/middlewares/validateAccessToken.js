const asyncHandler = require("express-async-handler");
const jwt = require("jsonwebtoken");
const User = require("../models/userModel");

const validateAccessToken = asyncHandler(async (req, res, next) => {
  try {
    let authHeader = req.headers.Authorization || req.headers.authorization;
    if (authHeader && authHeader.startsWith("Bearer")) {
      let token = authHeader.split(" ")[1];

      if (!token) {
        res.status(401);
        throw new Error("User is not authorized or token is missing!");
      }
      //   verify token
      jwt.verify(token, process.env.JWT_SECRET_KEY, (err, decoded) => {
        if (err) {
          res.status(401);
          throw new Error("User is not authorized");
        } else {
          const email = decoded.user.email;
          
          User.findOne({ where: { email } })
          .then((querySnipeShot)=>{
            // console.log(querySnipeShot.toJSON());
            req.user = querySnipeShot.get();
           
          })
          .then(()=>{
            next();
          })
          .catch((error)=>{
            res.status(404);
            throw new Error("NOT FOUND USER DATA :", error);
          });
        }
      });
    } else {
      res.status(400);
      throw new Error("Access Token not found");
    }
  } catch (error) {
    res.status(500);
    throw new Error("An error occured: ", error);
  }
});

module.exports = { validateAccessToken };
