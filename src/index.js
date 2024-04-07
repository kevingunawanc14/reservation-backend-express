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
const cron = require('node-cron');


const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization']

    const token = authHeader && authHeader.split(' ')[1]

    if (token == null) return res.sendStatus(401)

    jwt.verify(
        token,
        process.env.TOKEN_SECRET,
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
        const rolesArray = [...allowedRoles];
        console.log('roles yang haru dimiliki:', rolesArray)
        console.log('roles punya anda:', req.roles)
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
            const token = jwt.sign
                (
                    {
                        "UserInfo": {
                            "username": foundUser.username,
                            "roles": roles
                        }
                    },
                    process.env.TOKEN_SECRET,
                    { expiresIn: '1d' }
                );

            res.json({ token, username: foundUser.username });
        } else {
            res.sendStatus(401);
        }

    } catch (err) {
        console.log('err', err)
        res.status(500).json({ 'message': err.message });
    }
});

app.use(authenticateToken);

app.get('/search', verifyRoles(ROLES_LIST.User), async (req, res) => {
    // console.log('req', req);
    // console.log('query', req);
    const query = req.query.q

    if (!query) {
        return res.json([]); // Return empty array
    }

    try {
        const products = await prisma.product.findMany({
            where: {
                name: {
                    contains: query,
                }
            }
        });
        console.log(products, 'products')
        res.json(products);
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

app.get('/detail/:productId', verifyRoles(ROLES_LIST.User), async (req, res) => {
    try {
        const productId = parseInt(req.params.productId);
        const product = await prisma.product.findUnique({
            where: {
                id: productId
            }
        });

        res.json(product);
    } catch (error) {
        console.log(error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
})
app.get('/payment/:username', async (req, res) => {

    const { username } = req.params;

    try {
        const payments = await prisma.$queryRaw`
        SELECT
            hp.id,
            hp.username,
            hp.date,
            hp.totalPrice,
            hp.detailOrder,
            hp.createdAt,
            p.name AS productName
        FROM
            HistoryPayment hp
        LEFT JOIN
            Product p ON hp.idProduct = p.id
        WHERE
            hp.username = ${username}
        ORDER BY
            hp.id DESC;
        `;
        console.log('x2');
        // Send response with the retrieved payments
        res.json(payments);
    } catch (error) {
        // Handle errors
        console.error('Error fetching payments:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/user/detail/:username', async (req, res) => {
    try {
        const username = req.params.username;

        const user = await prisma.user.findUnique({
            where: {
                username: username
            }
        });

        if (user) {
            res.json(user);
        } else {
            res.status(404).json({ error: 'User not found' });
        }
    } catch (error) {
        console.log('error', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/dashboard', verifyRoles(ROLES_LIST.User), async (req, res) => {
    try {


        const totalReservations = null;
        const totalRevenue = null
        const totalProductsBySport = null
        const totalOrdersLast10Months = null
        const totalIncomeLast10Months = null

        res.json({
            totalReservations,
            totalRevenue,
            totalProductsBySport,
            totalOrdersLast10Months,
            totalIncomeLast10Months
        });
    } catch (error) {
        console.log('error', error)
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/dashboard/:id', verifyRoles(ROLES_LIST.User), async (req, res) => {
    try {
        const userId = parseInt(req.params.id);
        console.log('userId', userId)
        const user = await prisma.user.findUnique({
            where: {
                id: productId
            }
        });

        console.log('user', user)

        if (!user) {
            return res.status(404).json({ error: 'Product not found' });
        }

        res.json(user);
    } catch (error) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/dashboard/add', verifyRoles(ROLES_LIST.User), async (req, res) => {
    const { username, password } = req.body;

    try {
        const newUser = await prisma.user.create({
            data: {
                username,
                password
            }
        });

        res.status(201).json({ message: 'User added successfully', product: newUser });
    } catch (error) {
        console.error('Error adding user:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/dashboard/:id/update', verifyRoles(ROLES_LIST.User), async (req, res) => {
    const productId = parseInt(req.params.id);
    const { name, gor, price } = req.body; // Assuming these are the fields you want to update

    try {
        const existingProduct = await prisma.product.findUnique({
            where: { id: productId }
        });

        if (!existingProduct) {
            return res.status(404).json({ error: 'Product not found' });
        }

        const updateProduct = await prisma.product.update({
            where: { id: productId },
            data: {
                name: name || existingProduct.name,
                gor: gor || existingProduct.gor,
                price: price || existingProduct.price,
            }
        });

        res.json({ message: 'Product updated successfully', product: updateProduct });
    } catch (error) {
        console.log('error', error)
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.delete('/dashboard/:id', verifyRoles(ROLES_LIST.User), async (req, res) => {
    const productId = parseInt(req.params.id);
    console.log('productId', productId)
    try {
        const existingProduct = await prisma.product.findUnique({
            where: { id: productId }
        });

        if (!existingProduct) {
            return res.status(404).json({ error: 'Product not found' });
        }

        await prisma.product.delete({
            where: { id: productId }
        });

        res.json({ message: 'Product deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/order', verifyRoles(ROLES_LIST.User), async (req, res) => {
    try {
        const order = await prisma.schedule.findMany();
        res.json(order);
    } catch (error) {
        console.log(error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/order/:id', verifyRoles(ROLES_LIST.User), async (req, res) => {
    try {
        const orderId = parseInt(req.params.id);
        const order = await prisma.order.findUnique({
            where: {
                id: orderId
            }
        });

        if (!order) {
            return res.status(404).json({ error: 'Product not found' });
        }

        res.json(order);
    } catch (error) {
        console.log(error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/order/add', async (req, res) => {
    const { paymentMethod, paymentStatus } = req.body;

    try {
        const newOrder = await prisma.order.create({
            data: {
                paymentStatus,
                paymentMethod,
            }
        });

        res.status(201).json({ message: 'Order added successfully', order: newOrder });
    } catch (error) {
        console.error('Error adding order:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/order/:id/update', async (req, res) => {
    const orderId = parseInt(req.params.id);
    console.log(orderId);
    const { paymentMethod } = req.body; // Assuming these are the fields you want to update

    try {
        const existingOrder = await prisma.order.findUnique({
            where: { id: orderId }
        });

        if (!existingOrder) {
            return res.status(404).json({ error: 'Order not found' });
        }

        const updateOrder = await prisma.order.update({
            where: { id: orderId },
            data: {
                paymentMethod: paymentMethod || existingOrder.paymentMethod,
            }
        });

        res.json({ message: 'Order updated successfully', order: updateOrder });
    } catch (error) {
        console.log('error', error)
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.delete('/order/:id', async (req, res) => {
    const orderId = parseInt(req.params.id);
    try {
        const existingOrder = await prisma.order.findUnique({
            where: { id: orderId }
        });

        if (!existingOrder) {
            return res.status(404).json({ error: 'Order not found' });
        }

        await prisma.order.delete({
            where: { id: orderId }
        });

        res.json({ message: 'Order deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/order', async (req, res) => {
    try {
        const { idProduct, username, price, hour, paymentStatus, paymentMethod, totalPrice, date } = req.body;

        if (!hour) {
            const result = await prisma.schedule.create({
                data: {
                    idProduct: parseInt(idProduct),
                    username,
                    date,
                    hour: null,
                    paymentStatus,
                    paymentMethod,
                }
            });


        } else {
            const newSchedules = [];
            for (const h of hour) {
                const newSchedule = await prisma.schedule.create({
                    data: {
                        idProduct: parseInt(idProduct),
                        username,
                        price: price.toString(),
                        hour: h,
                        paymentStatus,
                        paymentMethod,
                        price: price.toString()
                    }
                });
                newSchedules.push(newSchedule);
            }

            res.json(newSchedules);
        }


        const historyPayment = await prisma.historyPayment.create({
            data: {
                idProduct: parseInt(idProduct),
                username,
                date,
                totalPrice: String(totalPrice),
                detailOrder: JSON.stringify(req.body),
            },
        });

        console.log('historyPayment', historyPayment);
        res.status(201).json({ message: 'Order added successfully', order: historyPayment });

    } catch (error) {
        console.error('Error inserting data:', error);
        res.status(500).json({ error: 'Error inserting data' });
    }
});

app.get('/user', verifyRoles(ROLES_LIST.User), async (req, res) => {
    try {
        const user = await prisma.user.findMany();
        res.json(user);
    } catch (error) {
        console.log('error', error)
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/user/:id', verifyRoles(ROLES_LIST.User), async (req, res) => {
    try {
        const userId = parseInt(req.params.id);
        const user = await prisma.user.findUnique({
            where: {
                id: userId
            }
        });

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json(user);
    } catch (error) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/user/add', async (req, res) => {
    const { username, password, phoneNumber } = req.body;
    console.log(req.body)
    try {
        const newUser = await prisma.user.create({
            data: {
                username,
                password,
                phoneNumber
            }
        });

        res.status(201).json({ message: 'User added successfully', product: newUser });
    } catch (error) {
        console.error('Error adding user:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/user/:id/update', async (req, res) => {
    const userId = parseInt(req.params.id);
    const { username, password, phoneNumber } = req.body;
    console.log(req.body);
    try {
        const existingUser = await prisma.user.findUnique({
            where: { id: userId }
        });

        if (!existingUser) {
            return res.status(404).json({ error: 'User not found' });
        }

        const updateUser = await prisma.user.update({
            where: { id: userId },
            data: {
                username: username || existingUser.username,
                password: password,
                phoneNumber: phoneNumber
            }
        });

        res.json({ message: 'User updated successfully', user: updateUser });
    } catch (error) {
        console.log('error', error)
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.delete('/user/:id', async (req, res) => {
    const userId = parseInt(req.params.id);
    try {
        const existingUser = await prisma.user.findUnique({
            where: { id: userId }
        });

        if (!existingUser) {
            return res.status(404).json({ error: 'User not found' });
        }

        await prisma.user.delete({
            where: { id: userId }
        });

        res.json({ message: 'User deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/product', verifyRoles(ROLES_LIST.User), async (req, res) => {
    try {
        const product = await prisma.product.findMany();
        console.log(product);
        res.json(product);
    } catch (error) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/product/:id', verifyRoles(ROLES_LIST.User), async (req, res) => {
    try {
        const productId = parseInt(req.params.id);
        console.log('productId', productId)
        const product = await prisma.product.findUnique({
            where: {
                id: productId
            }
        });

        console.log('product', product)

        if (!product) {
            return res.status(404).json({ error: 'Product not found' });
        }

        res.json(product);
    } catch (error) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/product/add', async (req, res) => {
    const { name, gor, price } = req.body;

    try {
        const newProduct = await prisma.product.create({
            data: {
                name,
                gor: parseInt(gor),
                price
            }
        });

        res.status(201).json({ message: 'Product added successfully', product: newProduct });
    } catch (error) {
        console.error('Error adding product:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/product/:id/update', async (req, res) => {
    const productId = parseInt(req.params.id);
    const { name, gor, price } = req.body; // Assuming these are the fields you want to update
    console.log(req.body)
    try {
        const existingProduct = await prisma.product.findUnique({
            where: { id: productId }
        });

        if (!existingProduct) {
            return res.status(404).json({ error: 'Product not found' });
        }

        const updateProduct = await prisma.product.update({
            where: { id: productId },
            data: {
                name: name || existingProduct.name,
                gor: parseInt(gor) || existingProduct.gor,
                price: price || existingProduct.price,
            }
        });

        res.json({ message: 'Product updated successfully', product: updateProduct });
    } catch (error) {
        console.log('error', error)
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.delete('/product/:id', async (req, res) => {
    const productId = parseInt(req.params.id);
    console.log('productId', productId)
    try {
        const existingProduct = await prisma.product.findUnique({
            where: { id: productId }
        });

        if (!existingProduct) {
            return res.status(404).json({ error: 'Product not found' });
        }

        await prisma.product.delete({
            where: { id: productId }
        });

        res.json({ message: 'Product deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/challenge', verifyRoles(ROLES_LIST.User), async (req, res) => {
    try {
        const challange = await prisma.challenge.findMany();
        console.log(challange);
        res.json(challange);
    } catch (error) {
        console.log('error', error)
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/challenge/:id', verifyRoles(ROLES_LIST.User), async (req, res) => {
    try {
        const challengeId = parseInt(req.params.id);
        console.log('challengeId', challengeId)
        const challenge = await prisma.challenge.findUnique({
            where: {
                id: challengeId
            }
        });

        console.log('challange', challenge)

        if (!challenge) {
            return res.status(404).json({ error: 'Challenge not found' });
        }

        res.json(challenge);
    } catch (error) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/challenge/add', async (req, res) => {
    const { description, repeatTime } = req.body;

    try {
        const newChallenge = await prisma.challenge.create({
            data: {
                description,
                repeatTime
            }
        });

        res.status(201).json({ message: 'Challenge added successfully', challenge: newChallenge });
    } catch (error) {
        console.error('Error adding challenge:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/challenge/:id/update', async (req, res) => {
    const challengeId = parseInt(req.params.id);
    const { description, repeatTime } = req.body; // Assuming these are the fields you want to update

    try {
        const existingChallenge = await prisma.challenge.findUnique({
            where: { id: challengeId }
        });

        if (!existingChallenge) {
            return res.status(404).json({ error: 'Challenge not found' });
        }

        const updatedChallenge = await prisma.challenge.update({
            where: { id: challengeId },
            data: {
                description: description || existingChallenge.description,
                repeatTime: repeatTime || existingChallenge.repeatTime,
            }
        });

        res.json({ message: 'Challenge updated successfully', challenge: updatedChallenge });
    } catch (error) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.delete('/challenge/:id', async (req, res) => {
    const challangeId = parseInt(req.params.id);
    console.log('challangeId', challangeId)
    try {
        const existingChallange = await prisma.challenge.findUnique({
            where: { id: challangeId }
        });

        if (!existingChallange) {
            return res.status(404).json({ error: 'Challange not found' });
        }

        await prisma.challenge.delete({
            where: { id: challangeId }
        });

        res.json({ message: 'challenge deleted successfully' });
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

// Update user status to sleep
const updateStatusToSleep = async () => {
    try {
        console.log('test');
        // Update statusDailyReward for all users
        const updatedUsers = await prisma.user.updateMany({
            data: {
                statusDailyReward: false
            }
        });

        console.log('User statusDailyReward updated successfully.');
    } catch (error) {
        console.error('Error updating user statusDailyReward:', error);
    }

};

// Cron job to update user status to sleep every minute
// cron.schedule('* * * * *', () => {
//     updateStatusToSleep();
// });


app.listen(PORT, () => {
    console.log("Express API running in port: " + PORT);
});