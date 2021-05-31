//Validation import
const Joi = require('joi')

const registrationValidation = async (body) => {
  //Defining Joi validation schema
  const schema = Joi.object({
    username: Joi.string().min(6).required(),
    email: Joi.string().min(6).required().email().lowercase(),
    password: Joi.string().min(6).required(),
  })
  return schema.validate(body)
}

const loginValidation = (body) => {
  //Defining Joi validation schema
  const schema = Joi.object({
    email: Joi.string().min(6).required().email().lowercase(),
    password: Joi.string().min(6).required(),
  })
  return schema.validate(body)
}

module.exports.registrationValidation = registrationValidation
module.exports.loginValidation = loginValidation
