const config = require('../config')
const { ValidationError } = require('joi')
const CustomErrorHandler = require('../utils/CustomError')
const { responder } = require('../constant/response') // add this import at top

const errorHandler = (err, req, res) => {
  let statusCode = 500
  let message = 'Internal server error'
  const extraData = {}

  // Include original error and stack trace only in DEBUG_MODE
  if (config.get('DEBUG_MODE') === 'true') {
    extraData.originalError = err.message
    extraData.stack = err.stack
  }

  if (err instanceof ValidationError) {
    statusCode = 422
    message = err.message
  }

  if (err instanceof CustomErrorHandler) {
    statusCode = err.status
    message = err.message
  }

  return responder(
    res,
    statusCode,
    message,
    Object.keys(extraData).length ? extraData : null
  )
}

module.exports = errorHandler
