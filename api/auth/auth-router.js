const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET, BCRYPT_NUM } = require("../secrets"); // use this secret!

const User = require('../users/users-model')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

router.post("/register", validateRoleName, async (req, res, next) => {
    try {
      const {password} = req.body;
      const hash = bcrypt.hashSync(password, BCRYPT_NUM)
      const newUser = await User.add({...req.body, password: hash});
      res.status(201).json(newUser);
    }catch (err){
      next(err)
    }
});


router.post("/login", checkUsernameExists, (req, res, next) => {
  const { user } = req
  if (bcrypt.compareSync(req.body.password, user.password)){
    const payload = {
      subject: user.user_id,
      username: user.username,
      role_name: user.role_name
    };
    const options = {
      expiresIn: '1d'
    };
    const token = jwt.sign(payload, JWT_SECRET, options)
    res.status(200).json({ message: `${user.username} is back!`, token })
  }else{
    next({ status: 401, message: "Invalid credentials" })
  }
});

module.exports = router;
