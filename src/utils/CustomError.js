class CustomErrorHandler extends Error {
  constructor(status, message, errorCode = null, hint = null) {
    super(message)
    this.status = status
    this.message = message
    this.errorCode = errorCode
    this.hint = hint
  }

  // 400 - Bad Request
  static badRequest(
    message = 'Bad request',
    errorCode = 'GEN_400',
    hint = 'Check the request parameters'
  ) {
    return new CustomErrorHandler(400, message, errorCode, hint)
  }

  // 401 - Unauthorized
  static unAuthorized(
    message = 'Unauthorized',
    errorCode = 'AUTH_001',
    hint = 'Ensure the Authorization header is set with a valid JWT token like: Bearer <token>'
  ) {
    return new CustomErrorHandler(401, message, errorCode, hint)
  }

  // 403 - Forbidden
  static forbidden(
    message = 'Access forbidden',
    errorCode = 'AUTH_403',
    hint = 'User does not have permission'
  ) {
    return new CustomErrorHandler(403, message, errorCode, hint)
  }

  // 404 - Not Found
  static notFound(
    message = 'Resource not found',
    errorCode = 'GEN_404',
    hint = 'Check the URL or resource ID'
  ) {
    return new CustomErrorHandler(404, message, errorCode, hint)
  }

  // 409 - Conflict
  static alreadyExist(
    message = 'Already exists',
    errorCode = 'DATA_001',
    hint = 'The record already exists in the system'
  ) {
    return new CustomErrorHandler(409, message, errorCode, hint)
  }

  // 422 - Unprocessable Entity (Validation errors)
  static unprocessableEntity(
    message = 'Unprocessable Entity',
    errorCode = 'VALIDATION_422',
    hint = 'Check form fields or request body'
  ) {
    return new CustomErrorHandler(422, message, errorCode, hint)
  }

  // 429 - Too Many Requests
  static tooManyRequests(
    message = 'Too many requests',
    errorCode = 'RATE_LIMIT_429',
    hint = 'Slow down your request rate'
  ) {
    return new CustomErrorHandler(429, message, errorCode, hint)
  }

  // 500 - Internal Server Error
  static serverError(message = 'Internal server error', errorCode = 'GEN_500') {
    return new CustomErrorHandler(500, message, errorCode)
  }

  // 503 - Service Unavailable
  static serviceUnavailable(
    message = 'Service unavailable',
    errorCode = 'GEN_503',
    hint = 'Try again later'
  ) {
    return new CustomErrorHandler(503, message, errorCode, hint)
  }

  // 401 - Wrong credentials
  static wrongCredentials(
    message = 'Username or password is wrong!',
    errorCode = 'AUTH_002'
  ) {
    return new CustomErrorHandler(401, message, errorCode)
  }

  // Custom Success (if ever needed in middleware for logic branching)
  static success(message = 'Success', errorCode = 'SUCCESS_200') {
    return new CustomErrorHandler(200, message, errorCode)
  }
}

module.exports = CustomErrorHandler
