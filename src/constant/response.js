const responder = (res, statusCode, message, data = null) => {
  res.status(statusCode).json({
    status: statusCode,
    success: statusCode >= 200 && statusCode < 300,
    message,
    count: Array.isArray(data) ? data.length : (data ? 1 : 0),
    timestamp: new Date().toISOString(),
    data
  })
}

module.exports = { responder }
