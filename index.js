import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import { authenticatedRoute, authenticateToken } from './utilities.js';
import User from './models/user.model.js';

const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET.trim();
const MONGO_PASSWORD = process.env.MONGO_PASSWORD.trim();
const app = express();

// Middleware setup
app.use(express.json());
app.use(cors({ origin: "*" })); // Allow all origins

// Connect to MongoDB
const CONNECTION_STRING = `mongodb+srv://AAU:${MONGO_PASSWORD}@atlascluster.aippciy.mongodb.net/?retryWrites=true&w=majority&appName=AtlasCluster`;

mongoose.connect(CONNECTION_STRING, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => {
    console.log('Successfully connected to MongoDB');
})
.catch((err) => {
    console.error('Error connecting to MongoDB', err);
});

// Routes
app.get('/', (req, res) => {
    res.json({ data: "Hello" });
});

// Create account
app.post("/createAccount", async (req, res) => {
    const { fullName, email, password } = req.body;
    if (!fullName || !email || !password) {
        return res.status(400).json({ error: "Full name, email, and password are required" });
    }

    const isUser = await User.findOne({ email });
    if (isUser) {
        return res.status(400).json({
            error: true,
            message: "User already exists"
        });
    }

    const user = new User({ fullName, email, password });
    await user.save();

    const accessToken = jwt.sign({ user }, ACCESS_TOKEN_SECRET, { expiresIn: "36000m" });

    return res.json({
        error: false,
        user,
        message: "User created successfully",
        accessToken
    });
});

// Login
app.post("/login", async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ message: "Email and password are required" });
    }

    const user = await User.findOne({ email });
    if (!user || user.password !== password) {
        return res.status(400).json({
            error: true,
            message: "Invalid credentials"
        });
    }

    const accessToken = jwt.sign({ user }, ACCESS_TOKEN_SECRET, { expiresIn: "3600000m" });

    return res.json({
        error: false,
        message: "User logged in successfully",
        accessToken
    });
});

// Get User
app.get("/get-user", authenticateToken, async (req, res) => {
    const { user } = req.user;
    const isUser = await User.findOne({ _id: user._id });
    if (!isUser) {
        return res.sendStatus(401);
    }
    return res.json({
        user: { fullName: isUser.fullName, email: isUser.email, _id: isUser._id, createdOn: isUser.createdOn },
        message: "",
    });
});

// Reset password
app.post("/reset-password", async (req, res) => {
    const { email, newPassword, confirmPassword } = req.body;
    if (!email || !newPassword || !confirmPassword) {
        return res.status(400).json({ message: "Email, new password, and confirm password are required" });
    }
    if (newPassword !== confirmPassword) {
        return res.status(400).json({ message: "Passwords do not match" });
    }

    const user = await User.findOne({ email });
    if (!user) {
        return res.status(400).json({ message: "User does not exist" });
    }

    // Update the user's password
    user.password = newPassword; // Hash this password before saving in production
    await user.save();

    return res.status(200).json({ message: "Password reset successful" });
});

// Start the server
const PORT = 4000;
app.listen(PORT, () => {
    console.log(`Server running on port number ${PORT}`);
});

export default app;
