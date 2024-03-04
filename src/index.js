const express = require("express");
const dotenv = require("dotenv");
const cors = require('cors')
const { PrismaClient } = require("@prisma/client");

dotenv.config();

const prisma = new PrismaClient();
const app = express();
const PORT = process.env.PORT;
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');


const verifyJWT = (req, res, next) => {
    const authHeader = req.headers.authorization || req.headers.Authorization;
    if (!authHeader?.startsWith('Bearer ')) return res.sendStatus(401);
    const token = authHeader.split(' ')[1];
    jwt.verify(
        token,
        process.env.ACCESS_TOKEN_SECRET,
        (err, decoded) => {
            if (err) return res.sendStatus(403); //invalid token
            req.user = decoded.UserInfo.username;
            req.roles = decoded.UserInfo.roles;
            next();
        }
    );
}

const verifyRoles = (...allowedRoles) => {
    return (req, res, next) => {
        if (!req?.roles) return res.sendStatus(401);
        console.log('req.role', req.roles)
        const rolesArray = [...allowedRoles];
        console.log('rolesArray', rolesArray)
        const result = req.roles.map(role => rolesArray.includes(role)).find(val => val === true);
        if (!result) return res.sendStatus(401);
        next();
    }
}

const ROLES_LIST = {
    "Admin": 5150,
    "Editor": 1984,
    "User": 2001
}

const allowedOrigins = [
    'https://www.yoursite.com',
    'http://localhost:5173',
    'http://localhost:2000'
];

const corsOptions = {
    origin: (origin, callback) => {
        if (allowedOrigins.indexOf(origin) !== -1 || !origin) {
            callback(null, true)
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    optionsSuccessStatus: 200
}

const credentials = (req, res, next) => {
    const origin = req.headers.origin;
    if (allowedOrigins.includes(origin)) {
        res.header('Access-Control-Allow-Credentials', true);
    }
    next();
}

app.use(credentials);
app.use(cors(corsOptions));
app.use(express.json())
app.use(cookieParser());

app.post('/register', async (req, res) => {
    const { username, password, phoneNumber } = req.body;

    if (!username || !password) return res.status(400).json({ 'message': 'Username and password are required.' });
    // check for duplicate usernames in the db
    const duplicate = await prisma.user.findUnique({
        where: {
            username: username,
        },
    });
    if (duplicate) return res.sendStatus(409); //Conflict 
    try {
        //encrypt the password
        const hashedPwd = await bcrypt.hash(password, 10);

        //store the new user
        const newUser = await prisma.user.create({
            data: {
                username: username,
                password: hashedPwd,
                phoneNumber: phoneNumber,
                roles: { "User": 2001 }
            },
        });
        console.log("Created user: ", newUser);
        res.status(201).json({ 'success': `New user  created!` });

    } catch (err) {
        console.log(err);
        res.status(500).json({ 'message': err.message });
    }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ 'message': 'Username and password are required.' });

    try {
        const foundUser = await prisma.user.findUnique({
            where: {
                username: username,
            },
        });

        if (!foundUser) return res.status(401).json({ message: 'User not found' });

        const match = await bcrypt.compare(password, foundUser.password);

        if (match) {
            const roles = Object.values(foundUser.roles);
            // create JWTs
            const accessToken = jwt.sign(
                {
                    "UserInfo": {
                        "username": foundUser.username,
                        "roles": roles
                    }
                },
                process.env.ACCESS_TOKEN_SECRET,
                { expiresIn: '30s' }
            );
            const refreshToken = jwt.sign(
                { "username": foundUser.username },
                process.env.REFRESH_TOKEN_SECRET,
                { expiresIn: '1d' }
            );
            await prisma.user.update({
                where: {
                    username: username
                },
                data: {
                    refreshToken: refreshToken
                }
            });
            res.cookie('jwt', refreshToken, { httpOnly: true, sameSite: 'None', secure: true, maxAge: 24 * 60 * 60 * 1000 });
            res.json({ accessToken, roles });
        } else {
            res.sendStatus(401);
        }

    } catch (err) {
        res.status(500).json({ 'message': err.message });
    }
});

app.post('/logout', async (req, res) => {
    // On client, also delete the accessToken
    const cookies = req.cookies;
    if (!cookies?.jwt) return res.sendStatus(204); //No content
    const refreshToken = cookies.jwt;

    // Is refreshToken in db?
    const foundUser = await prisma.user.findFirst({
        where: {
            refreshToken: refreshToken,
        },
    });
    if (!foundUser) {
        res.clearCookie('jwt', { httpOnly: true, sameSite: 'None', secure: true });
        return res.sendStatus(204);
    }

    // Delete refreshToken in db
    await prisma.user.update({
        where: {
            username: foundUser.username,
            refreshToken: refreshToken,
        },
        data: {
            refreshToken: '', // Provide the new value for the refresh token here
        },
    });

    res.clearCookie('jwt', { httpOnly: true, sameSite: 'None', secure: true });
    res.sendStatus(204);
});

app.get('/refresh', async (req, res) => {
    const cookies = req.cookies
    if (!cookies?.jwt) return res.status(401);
    const refreshToken = cookies.jwt;
    const foundUser = await prisma.user.findFirst({
        where: {
            refreshToken: refreshToken,
        },
    });
    if (!foundUser) return res.status(403).json({ message: 'User not found' });

    jwt.verify(
        refreshToken,
        process.env.REFRESH_TOKEN_SECRET,
        (err, decoded) => {
            if (err || foundUser.username !== decoded.username) return res.sendStatus(403);
            const roles = Object.values(foundUser.roles);
            const accessToken = jwt.sign(
                {
                    "UserInfo": {
                        "username": decoded.username,
                        "roles": roles
                    }
                },
                process.env.ACCESS_TOKEN_SECRET,
                { expiresIn: '30s' }
            );
            res.json({ roles, accessToken })
        }
    )

});

app.use(verifyJWT);

app.get('/search', verifyRoles(ROLES_LIST.User), async (req, res) => {
    const { query } = req.query;

    // Check if name is empty
    if (!query) {
        return res.json([]); // Return empty array
    }
    try {
        const courts = await prisma.court.findMany({
            where: {
                name: {
                    contains: query,
                }
            }
        });
        console.log(courts, 'courts')
        res.json(courts);
    } catch (error) {
        console.error('Error searching courts:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/detail', async (req, res) => {
    const { name } = req.query;
    console.log('name', name)

    // Check if name is empty
    if (!name) {
        return res.json([]); // Return empty array
    }
    try {
        const courts = await prisma.court.findMany({
            where: {
                name: {
                    contains: name,
                }
            }
        });
        console.log(courts, 'courts')
        res.json(courts);
    } catch (error) {
        console.error('Error searching courts:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get("/api", (req, res) => {
    res.send("Hello World test");
})

app.get("/products", async (req, res) => {
    const products = await prisma.product.findMany();

    res.send(products);
})

app.post("/products", async (req, res) => {

    const newProductData = req.body;
    console.log(newProductData, 'x');
    const products = await prisma.product.create({
        data: {
            name: newProductData.name,
        }
    });

    res.send({
        data: products,
        message: "success"
    });
})

app.get('/users', verifyRoles(ROLES_LIST.User), async (req, res) => {
    try {
        const users = await prisma.user.findMany();
        res.json(users);
    } catch (error) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/courts', verifyRoles(ROLES_LIST.User), async (req, res) => {
    try {
        const users = await prisma.user.findMany();
        res.json(users);
    } catch (error) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.delete('/users/:id', async (req, res) => {
    const userId = parseInt(req.params.id);
    try {
        // Check if the user exists
        const existingUser = await prisma.user.findUnique({
            where: { id: userId }
        });
        if (!existingUser) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Delete the user
        await prisma.user.delete({
            where: { id: userId }
        });

        res.json({ message: 'User deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/journals', async (req, res) => {
    try {
        const journals = await prisma.journal.findMany();
        res.json(journals);
    } catch (error) {
        console.error('Error fetching journals:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.listen(PORT, () => {
    console.log("Express API running in port: " + PORT);
});