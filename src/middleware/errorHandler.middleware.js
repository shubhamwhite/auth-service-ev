const config = require('../config')
const { ValidationError } = require('joi')
const CustomErrorHandler = require('../utils/CustomError')
const { responder } = require('../constant/response')

const errorHandler = (err, req, res, next) => {
  let statusCode = 500
  let message = 'Internal server error'
  const extraData = {
    timestamp: new Date().toISOString()
  }

  // Show originalError and stack only if DEBUG_MODE is true
  if (config.get('DEBUG_MODE') === 'true') {
    extraData.originalError = err.message
    extraData.stack = err.stack
  }

  // Handle Joi validation error
  if (err instanceof ValidationError) {
    statusCode = 422
    message = err.message
  }

  // Handle custom error
  if (err instanceof CustomErrorHandler) {
    statusCode = err.status
    message = err.message
    if (err.errorCode) {
      extraData.errorCode = err.errorCode
    }
    if (err.hint) {
      extraData.hint = err.hint
    }
  }

  return responder(
    res,
    statusCode,
    message,
    Object.keys(extraData).length ? extraData : null
  )
}

module.exports = errorHandler
