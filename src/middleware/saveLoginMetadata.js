exports.saveLoginMetadata = (req, res, next) => {
  const ip =
    req.headers['x-forwarded-for']?.split(',').shift() ||
    req.socket?.remoteAddress ||
    null

  const userAgent = req.get('User-Agent') || null

  req.metadata = {
    ip_address: ip,
    last_login_ip: ip,
    user_agent: userAgent
  }

  next()
}
