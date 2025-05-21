const Joi = require('joi')

const signupValidationSchema = (req, res, next) => {
  const schema = Joi.object({
    first_name: Joi.string().min(3).max(50).required().messages({
      'string.empty': 'First name is required',
      'string.min': 'First name must be at least 3 characters',
      'string.max': 'First name must not exceed 50 characters'
    }),
    last_name: Joi.string().min(3).max(50).required().messages({
      'string.empty': 'Last name is required',
      'string.min': 'Last name must be at least 3 characters',
      'string.max': 'Last name must not exceed 50 characters'
    }),
    email: Joi.string().email().required().messages({
      'string.email': 'Invalid email format',
      'string.empty': 'Email is required'
    }),
    password: Joi.string().min(6).required().messages({
      'string.min': 'Password must be at least 6 characters',
      'string.empty': 'Password is required'
    }),
    repeat_password: Joi.string()
      .valid(Joi.ref('password'))
      .required()
      .messages({
        'any.only': 'Password and repeat password do not match',
        'string.empty': 'Repeat password is required'
      })
  })

  const { error } = schema.validate(req.body, { abortEarly: false })

  if (error) {
    return next(error)
  }

  next()
}

const loginValidationSchema = (req, res, next) => {
  const schema = Joi.object({
    email: Joi.string().email().required().messages({
      'string.email': 'Invalid email format',
      'string.empty': 'Email is required'
    }),
    password: Joi.string().required().messages({
      'string.empty': 'Password is required'
    })
  })

  const { error } = schema.validate(req.body, { abortEarly: false })

  if (error) {
    return next(error)
  }

  next()
}

module.exports = { signupValidationSchema, loginValidationSchema }
