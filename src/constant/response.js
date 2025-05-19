const responder = (res, statusCode, message, data = null) => {
  res.status(statusCode).json({
    status: statusCode,
    message,
    data
  })
}

module.exports = { responder }
