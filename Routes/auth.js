//Import required packages
const router = require('express').Router()
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
//Import files
const User = require('../Models/User')
const { registrationValidation, loginValidation } = require('../Validation')

router.post('/register', async (req, res) => {
  //imported from Joi validation
  const { error, value } = await registrationValidation(req.body)
  if (error) return res.status(400).send(error.details[0].message)

  //Value from validation
  const { username, email, password } = value

  //Check that email does not already exists
  const emailExists = await User.findOne({ email: email }) //  we can also write this ({email})
  if (emailExists) return res.status(400).send('Email already exists')

  const usernameExists = await User.findOne({ username: username }) //  we can also write this ({name})
  if (usernameExists) return res.status(400).send('Username already exists')

  //Hashing the Password
  const salt = await bcrypt.genSalt(10)
  const HashedPassord = await bcrypt.hash(password, salt)

  //Create new user in database
  const user = new User({
    username: username,
    email: email,
    password: HashedPassord,
  })

  try {
    const savedUser = await user.save()
    res.send(savedUser)
  } catch (err) {
    res.status(400).send(err)
  }
})

router.post('/login', async (req, res) => {
  //imported from Joi validation
  const { error, value } = loginValidation(req.body)
  if (error) return res.status(400).send(error.details[0].message)

  //Value from validation
  const { email, password } = value

  //Check that email exists
  const user = await User.findOne({ email: email }) //  we can also write this ({email})
  if (!user) return res.status(400).send('invalid Email or Password')

  //comparing Password
  const HashedPassord = await bcrypt.compare(password, user.password)
  if (!HashedPassord) return res.status(400).send('invalid Email or Password')
  if (!user.isVerified)
    return res.status(400).json({ error: 'your account is not verified please verify' })

  //creating jwt token
  const token = jwt.sign({ _id: user._id }, process.env.TOKEN_SECRET)

  res.header('auth-token', token).send(token)
})

module.exports = router
