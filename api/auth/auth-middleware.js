const { JWT_SECRET } = require("../secrets"); // use this secret!
const { findBy } = require('../users/users-model')

const restricted = (req, res, next) => {
  /*
    If the user does not provide a token in the Authorization header:
    status 401
    {
      "message": "Token required"
    }

    If the provided token does not verify:
    status 401
    {
      "message": "Token invalid"
    }

    Put the decoded token in the req object, to make life easier for middlewares downstream!
  */
    next()
}

const only = role_name => (req, res, next) => {
  /*
    If the user does not provide a token in the Authorization header with a role_name
    inside its payload matching the role_name passed to this function as its argument:
    status 403
    {
      "message": "This is not for you"
    }

    Pull the decoded token from the req object, to avoid verifying it again!
  */
    next()
}


const checkUsernameExists = async (req, res, next) => {
  /*
    If the username in req.body does NOT exist in the database
    status 401
    {
      "message": "Invalid credentials"
    }
  */
    try{
      const { username } = req.body;
      const [user] = await findBy({username});
      if (user) {
        req.user = user;
        next();
      }else{
        next({ status: 401, message: "Invalid credentials" })
      }
    } catch (err) {
      next(err);
    }
}


const validateRoleName = (req, res, next) => {
    const { role_name } = req.body
    if (
      role_name 
      && typeof role_name === 'string' 
      && role_name.trim() !== ''
    ){
      const role_trim = role_name.trim()
      if (
        role_trim !== 'admin'
        && role_trim.length < 33
      ){
        req.body.role_name = role_trim
        next()
      }else if (role_trim === 'admin'){
        next({ status: 422, message: "Role name can not be admin" })
      }else if (role_trim.length > 32){
        next({ status: 422, message: "Role name can not be longer than 32 chars" })
      }else{
        next({ status: 500, message: "Server configuration error"})
      }
    }else{
      req.body.role_name = 'student'
      next()
    }
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
