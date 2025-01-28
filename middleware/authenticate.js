// middleware/authenticate.js
const jwt = require('jsonwebtoken');

const authenticate = (req, res, next) => {
  const token = req.header('x-auth-token');
  
  if (!token) {
    return res.status(401).send('Access denied. No token provided.');
  }

  try {
    const decoded = jwt.verify(token, 'your_jwt_secret_key');  // Replace with your secret key
    req.userId = decoded.id;  // Attach user id to the request
    req.username = decoded.username;  // Attach username to request for role checking
    next();  // Proceed to the next middleware or route handler
  } catch (err) {
    res.status(400).send('Invalid token.');
  }
};

module.exports = authenticate;
