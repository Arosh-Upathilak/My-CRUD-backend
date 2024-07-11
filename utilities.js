import jwt from "jsonwebtoken";


const ACCESS_TOKEN_SECRET = encodeURIComponent(process.env.ACCESS_TOKEN_SECRET.trim());

// Middleware to authenticate token
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.sendStatus(401);

    jwt.verify(token, ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) {
            console.error(err);
            return res.sendStatus(403);
        }
        req.user = user;
        next();
    });
}

// Example middleware for authenticated routes
function authenticatedRoute(req, res, next) {
    // Example logic to check if user is authenticated
    if (!req.user) {
        return res.sendStatus(401);
    }
    // Proceed to the next middleware
    next();
}

export { authenticateToken, authenticatedRoute };
