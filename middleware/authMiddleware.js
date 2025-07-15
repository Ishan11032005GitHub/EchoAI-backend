import jwt from 'jsonwebtoken';

const authMiddleware = (req, res, next) => {
  console.log("🔐 Incoming Auth Header:", req.headers.authorization); // 👈 ADD THIS LINE

  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: 'No token provided' });

  const token = req.cookies.token || authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (err) {
    return res.status(403).json({ message: 'Invalid token' });
  }
};

export default authMiddleware;
