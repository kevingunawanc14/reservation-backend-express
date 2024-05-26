const express = require("express");
const dotenv = require("dotenv");
const cors = require('cors')
const { PrismaClient } = require("@prisma/client");

dotenv.config();

const prisma = new PrismaClient();
const app = express();
const PORT = 2000;
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const cron = require('node-cron');
const multer = require('multer');
const path = require('path');


const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization']

    const token = authHeader && authHeader.split(' ')[1]
    if (token == null) return res.sendStatus(401)

    jwt.verify(
        token,
        '501a3eb5937c1195b380eed1657d147acebf0e2a8403c519dd0ec809186e04fe5716f52b1773b3292561a2fb7792fbfdd56b2b6957af16aca530f754bfe437db',
        (err, decoded) => {
            if (err) return res.sendStatus(403);
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
        const result = req.roles.map(role => rolesArray.includes(role)).find(val => val === true);
        if (!result) return res.sendStatus(401);
        next();
    }
}

const ROLES_LIST = {
    "Admin": 5150,
    "User": 2001
}

const allowedOrigins = [
    'http://localhost:5173',
    'https://krakatausportcentrejombang.cloud'
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

app.get('/api', (req, res) => {
    res.send('Hello World');
});

app.post('/api/register', async (req, res) => {
    const { username, password, phoneNumber } = req.body;

    if (!username) {
        return res.status(400).json({ error: 'Username is required' });
    }
    if (username.length < 5) {
        return res.status(400).json({ error: 'Username must be at least 5 characters' });
    }
    if (!password) {
        return res.status(400).json({ error: 'Password is required' });
    }
    const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/;
    if (!passwordRegex.test(password)) {
        return res.status(400).json({ error: 'Password not valid' });
    }
    if (!phoneNumber) {
        return res.status(400).json({ error: 'Phone number is required' });
    }
    if (phoneNumber.length !== 12) {
        return res.status(400).json({ error: 'Phone number must be 12 digits' });
    }

    const existingUser = await prisma.user.findUnique({
        where: { username: username },
    });

    if (existingUser) {
        return res.status(400).json({ error: 'Please use another username' });
    }

    try {
        const hashedPwd = await bcrypt.hash(password, 10);

        await prisma.user.create({
            data: {
                username: username,
                password: hashedPwd,
                phoneNumber: phoneNumber,
                roles: { "User": 2001 }
            },
        });

        await prisma.historyAvatar.create({
            data: {
                username: username,
                avatar: 'GiMuscleFat',
            },
        });

        await prisma.historyTheme.create({
            data: {
                username: username,
                theme: 'Light',
            },
        });

        res.status(201).json({ 'success': `New user  created!` });

    } catch (error) {
        console.log('error', error)
        res.status(500).json({ 'message': error.message });
    }
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username) {
        return res.status(400).json({ error: 'Username is required' });
    }
    if (!password) {
        return res.status(400).json({ error: 'Password is required' });
    }
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
            const token = jwt.sign
                (
                    {
                        "UserInfo": {
                            "username": foundUser.username,
                            "roles": roles
                        }
                    },
                    '501a3eb5937c1195b380eed1657d147acebf0e2a8403c519dd0ec809186e04fe5716f52b1773b3292561a2fb7792fbfdd56b2b6957af16aca530f754bfe437db',
                    { expiresIn: '1d' }
                );

            res.json({ token, username: foundUser.username });
        } else {
            res.sendStatus(401);
        }

    } catch (error) {
        console.log('error', error)
        res.status(500).json({ 'message': error.message });
    }
});

app.use('/api/images', express.static(path.join(__dirname, '..', 'images')));
console.log('dirname', __dirname)
console.log('path', path.join(__dirname, '..', 'images'))


app.use(authenticateToken);

app.get('/api/search', verifyRoles(ROLES_LIST.User), async (req, res) => {
    const query = req.query.q

    if (!query) {
        return res.json([]);
    }

    try {
        const products = await prisma.product.findMany({
            where: {
                name: {
                    contains: query,
                }
            }
        });
        res.json(products);
    } catch (error) {
        console.log('error', error)
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/api/progressive-challange/:username', verifyRoles(ROLES_LIST.User), async (req, res) => {
    const { username } = req.params;
    try {
        const today = new Date();

        const startOfWeek = new Date(today);
        startOfWeek.setDate(today.getDate() - today.getDay());
        const endOfWeek = new Date(today);
        endOfWeek.setDate(startOfWeek.getDate() + 6);

        const scheduleCountWeekly = await prisma.schedule.count({
            where: {
                username: username,
                AND: [
                    { date: { gte: startOfWeek.toISOString() } },
                    { date: { lte: endOfWeek.toISOString() } }
                ]
            }
        });


        const startOfMonth = new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), 1));
        const endOfMonth = new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth() + 1, 0));

        const scheduleCountMonthly = await prisma.schedule.count({
            where: {
                username: username,
                AND: [
                    { date: { gte: startOfMonth.toISOString() } },
                    { date: { lte: endOfMonth.toISOString() } }
                ]
            }
        });

        const currentMonth = today.getMonth() + 1;

        let startOfYear, endOfYear;
        if (currentMonth <= 6) {
            startOfYear = new Date(Date.UTC(today.getUTCFullYear(), 0, 1));
            endOfYear = new Date(Date.UTC(today.getUTCFullYear(), 5, 30));
        } else {
            startOfYear = new Date(Date.UTC(today.getUTCFullYear(), 6, 1));
            endOfYear = new Date(Date.UTC(today.getUTCFullYear(), 11, 31));
        }

        const scheduleCount6Month = await prisma.schedule.count({
            where: {
                username: username,
                AND: [
                    { date: { gte: startOfYear.toISOString() } },
                    { date: { lte: endOfYear.toISOString() } }
                ]
            }
        });

        res.status(200).json({
            hourWeekly: scheduleCountWeekly,
            hourMonthly: scheduleCountMonthly,
            hour6Month: scheduleCount6Month
        });
    } catch (error) {
        console.log('error', error)
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/claim-reward/:username', verifyRoles(ROLES_LIST.User), async (req, res) => {
    const username = req.params.username;
    const { valueReward, type } = req.body;
    // console.log('req.body', req.body)
    try {
        let fieldToUpdate;
        switch (type) {
            case 1:
                fieldToUpdate = 'experiencePoint';
                break;
            case 2:
                fieldToUpdate = 'healthPoint';
                break;
            case 3:
                fieldToUpdate = 'attackPoint';
                break;
            case 4:
                fieldToUpdate = 'defensePoint';
                break;
            default:
                const updatedUser = await prisma.user.update({
                    where: { username },
                    data: {
                        statusDailyReward: true,
                    }
                });
                return res.status(200).json({ type, valueReward, updatedUser });
        }
        const updatedUser = await prisma.user.update({
            where: { username },
            data: {
                statusDailyReward: valueReward <= 3 ? true : undefined,
                statusWeeklyChallange: valueReward === 10 ? true : undefined,
                statusMonthlyChallange: valueReward === 100 ? true : undefined,
                status6MonthChallange: valueReward === 1000 ? true : undefined,
                [fieldToUpdate]: {
                    increment: valueReward
                }
            }
        });

        res.status(200).json({ ...updatedUser, type, valueReward });
    } catch (error) {
        console.log('error', error)
        res.status(500).send('Internal Server Error');
    }
});

app.get('/api/product', verifyRoles(ROLES_LIST.User), async (req, res) => {
    try {
        const product = await prisma.product.findMany();
        res.json(product);
    } catch (error) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/api/detail/:productId', verifyRoles(ROLES_LIST.User), async (req, res) => {
    try {
        const productId = parseInt(req.params.productId);
        const product = await prisma.product.findUnique({
            where: {
                id: productId
            }
        });

        res.json(product);
    } catch (error) {
        console.log('error', error)
        res.status(500).json({ error: 'Internal Server Error' });
    }
})

app.get('/api/journal/:username', verifyRoles(ROLES_LIST.User), async (req, res) => {

    const { username } = req.params;

    try {
        const payments = await prisma.$queryRaw`
        SELECT
            hp.*,
            p.name AS productName
        FROM
            HistoryPayment hp
        LEFT JOIN
            Product p ON hp.idProduct = p.id
        WHERE
            hp.username = ${username}
            AND 
            hp.idProduct NOT IN (16, 17, 18, 19, 20, 21)
            AND
            hp.paymentStatus = 'Lunas'
        ORDER BY
            hp.id DESC;
        `;

        res.json(payments);
    } catch (error) {
        console.log('error', error)
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/payment/:username', verifyRoles(ROLES_LIST.User), async (req, res) => {

    const { username } = req.params;

    try {
        const payments = await prisma.$queryRaw`
        SELECT
            hp.*,
            p.name AS productName,
            p.nameDetail as fullProductName
        FROM
            HistoryPayment hp
        LEFT JOIN
            Product p ON hp.idProduct = p.id
        WHERE
            hp.username = ${username}
        ORDER BY
            hp.id DESC;
        `;

        res.json(payments);
    } catch (error) {
        console.log('error', error)
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/attack/:username', verifyRoles(ROLES_LIST.User), async (req, res) => {
    const { username } = req.params;
    const userLogin = req.user

    // console.log(username)
    try {
        const user = await prisma.user.findUnique({ where: { username: username } });

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        let updatedUser;
        if (user.defensePoint > 0) {
            updatedUser = await prisma.user.update({
                where: { username: username },
                data: { defensePoint: user.defensePoint - 1 },
            });
        } else {
            updatedUser = await prisma.user.update({
                where: { username: username },
                data: { healthPoint: user.healthPoint - 1 },
            });
        }

        updatedUserLogin = await prisma.user.update({
            where: { username: userLogin },
            data: {
                attackPoint: {
                    decrement: 1
                }
            },
        });

        res.json({
            updatedUser,
            updatedUserLogin,
        });
    } catch (error) {
        console.log('error', error)
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/user/detail/:username', verifyRoles(ROLES_LIST.User), async (req, res) => {
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

app.get('/api/user/detail/stat/:username', verifyRoles(ROLES_LIST.User), async (req, res) => {
    try {
        const totalMinuteWorkout = await prisma.schedule.count({
            where: {
                idProduct: { lte: 16 }
            }
        }); const mostPlayedSport = await prisma.$queryRaw`
            SELECT s.idProduct, p.name AS productName, COUNT(s.idProduct) AS productCount
            FROM Schedule s
            JOIN Product p ON s.idProduct = p.id
            GROUP BY s.idProduct, p.name
            ORDER BY productCount DESC
            LIMIT 1;
        `;
        const typeSport = mostPlayedSport[0].idProduct > 16 ? "Individual" : "Team";

        res.status(200).json({
            totalMinuteWorkout: totalMinuteWorkout,
            mostPlayedSport: mostPlayedSport[0].productName,
            typeSport: typeSport
        });

    } catch (error) {
        console.log('error', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/api/user/detail/avatar/:username', verifyRoles(ROLES_LIST.User), async (req, res) => {
    try {
        const { username } = req.params;

        const userAvatars = await prisma.historyAvatar.findMany({
            where: {
                username: username
            }
        });

        if (userAvatars.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.status(200).json(userAvatars);
    } catch (error) {
        console.log('error', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/api/user/detail/theme/:username', verifyRoles(ROLES_LIST.User), async (req, res) => {
    try {
        const { username } = req.params;

        const userTheme = await prisma.historyTheme.findMany({
            where: {
                username: username
            }
        });

        if (userTheme.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.status(200).json(userTheme);
    } catch (error) {
        console.log('error', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/api/user/detail/achievement/:username', verifyRoles(ROLES_LIST.User), async (req, res) => {
    const { username } = req.params;

    try {
        const sumReservation = await prisma.schedule.count({
            where: {
                username: username
            }
        });

        const sumBadminton = await prisma.schedule.count({
            where: {
                username: username,
                idProduct: {
                    in: [3, 4, 5, 10, 11, 12, 13]
                }
            }
        });

        const sumFutsal = await prisma.schedule.count({
            where: {
                username: username,
                idProduct: {
                    in: [2, 9]
                }
            }
        });

        const sumBasketball = await prisma.schedule.count({
            where: {
                username: username,
                idProduct: {
                    in: [1, 6, 7, 8, 14, 15]
                }
            }
        });

        const sumGym = await prisma.schedule.count({
            where: {
                username: username,
                idProduct: {
                    in: [20, 21]
                }
            }
        });

        res.json({
            sumReservation,
            sumBadminton,
            sumFutsal,
            sumBasketball,
            sumGym
        });
    } catch (error) {
        console.log('error', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/api/buy-avatar', verifyRoles(ROLES_LIST.User), async (req, res) => {
    try {
        const username = req.user
        const { avatar, price } = req.body;

        const newAvatarHistory = await prisma.historyAvatar.create({
            data: {
                username,
                avatar
            }
        });

        const user = await prisma.user.update({
            where: { username: username },
            data: {
                experiencePoint: {
                    decrement: price,
                },
            },
        });

        res.status(200).json(newAvatarHistory);

    } catch (error) {
        console.log('error', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/api/update-avatar', verifyRoles(ROLES_LIST.User), async (req, res) => {
    try {
        const { activeAvatar } = req.body;
        const username = req.user
        // console.log('activeAvatar', activeAvatar)

        const updatedUser = await prisma.user.update({
            where: {
                username: username
            },
            data: {
                activeAvatar: activeAvatar
            }
        });

        res.status(200).json(updatedUser);

    } catch (error) {
        console.log('error', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/api/user/detail-theme', verifyRoles(ROLES_LIST.User), async (req, res) => {
    try {
        const username = req.user

        const ownedTheme = await prisma.historyTheme.findMany({
            where: {
                username: username
            }
        });

        res.status(200).json(ownedTheme);
    } catch (error) {
        console.log('error', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/api/buy-theme', verifyRoles(ROLES_LIST.User), async (req, res) => {
    try {
        const username = req.user
        const { theme, price } = req.body;

        const newThemeHistory = await prisma.historyTheme.create({
            data: {
                username,
                theme
            }
        });

        const user = await prisma.user.update({
            where: { username: username },
            data: {
                experiencePoint: {
                    decrement: price,
                },
            },
        });

        res.status(200).json(newThemeHistory);

    } catch (error) {
        console.log('error', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/api/update-theme', verifyRoles(ROLES_LIST.User), async (req, res) => {
    try {
        const { activeTheme, username } = req.body;
        // console.log('activeTheme', activeTheme)
        // console.log('username', username)

        const updatedUser = await prisma.user.update({
            where: {
                username: username
            },
            data: {
                activeTheme: activeTheme
            }
        });

        res.status(200).json(updatedUser);

    } catch (error) {
        console.log('error', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/api/order/reserved', verifyRoles(ROLES_LIST.User), async (req, res) => {
    try {
        const order = await prisma.schedule.findMany();
        res.json(order);
    } catch (error) {
        console.log('error', error)
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/api/order/detail/:id', verifyRoles(ROLES_LIST.User), async (req, res) => {
    try {
        const connectHistory = req.params.id;
        const detailOrder = await prisma.$queryRaw`
            SELECT * FROM Schedule
            WHERE connectHistory = ${connectHistory};
        `;
        console.log('detailOrder', detailOrder)
        console.log('detailOrder.length', detailOrder.length)

        if (detailOrder.length == 0) {
            return res.status(404).json({ status: 'fail', message: `Please refresh the page reservation already canceled` });

        }
        // console.log('detailOrder', detailOrder);
        res.json(detailOrder);
    } catch (error) {
        console.log('error', error)
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'images')
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname))
    }
})

const upload = multer({ storage: storage })

app.post('/api/order', verifyRoles(ROLES_LIST.User), upload.single('filePaymentProve'), async (req, res) => {
    // console.log('Uploaded file:', req.file);
    // console.log('req:', req);
    // console.log('req.file.filename:', req.file.filename);
    // console.log('check2')

    // console.log('req:', req);
    // console.log('res:', res);
    // const imageUrl = `/bukti_pembayaran_qris/${req.file.filename}`;

    try {
        const {
            idProduct,
            username,
            hour,
            paymentStatus,
            paymentMethod,
            totalPrice,
            date,
            detailDate,
            typeBreath,
            minuteBreath,
            totalXp,
            totalHp,
            totalAttack,
            totalDefense,
            connectHistory,
            cancelId,
        } = req.body;

        const hourArray = hour.split(',');


        // console.log('typeBreath', typeBreath)
        // console.log('minuteBreath', minuteBreath)
        // console.log('totalXp', totalXp)
        // console.log('totalHp', totalHp)
        // console.log('totalAttack', totalAttack)
        // console.log('totalDefense', totalDefense)
        // console.log('totalPrice', totalPrice)
        // console.log('paymentMethod', paymentMethod)
        console.log('hourArray', hourArray)
        console.log('date', date)

        console.log('req.body', req.body);

        // Check if any hour in the array is already booked
        for (const hour of hourArray) {
            const existingSchedule = await prisma.schedule.findFirst({
                where: {
                    hour,
                    date,
                    idProduct: parseInt(idProduct)
                },
            });

            if (existingSchedule) {
                return res.status(400).json({ status: 'fail', message: `Please refresh the page date and hour ${hour} already ordered` });
            }
        }

        if (hour == 'null') {
            const result = await prisma.schedule.create({
                data: {
                    idProduct: parseInt(idProduct),
                    username,
                    date,
                    hour: null,
                    connectHistory,
                    cancelId
                }
            });
        } else {

            const sortedHours = hourArray.sort((a, b) => {
                const [aStart] = a.split('-');
                const [bStart] = b.split('-');
                return parseFloat(aStart) - parseFloat(bStart);
            });

            const idProductMappings = {
                1: [2, 3, 4, 5, 6, 7, 1],
                2: [1, 3, 4, 5, 6, 7, 2],
                3: [1, 2, 3],
                4: [1, 2, 4],
                5: [1, 2, 7, 5],
                6: [1, 2, 6],
                7: [1, 2, 7],
                8: [9, 10, 11, 12, 13, 14, 15, 8],
                9: [8, 10, 11, 12, 13, 14, 15, 9],
                10: [8, 9, 14, 10],
                11: [8, 9, 14, 11],
                12: [8, 9, 15, 12],
                13: [8, 9, 15, 13],
                14: [1, 2, 10, 11, 14],
                15: [1, 2, 12, 13, 15]
            };

            for (const h of sortedHours) {
                const idsToInsert = idProductMappings[idProduct];
                for (const productId of idsToInsert) {
                    await prisma.schedule.create({
                        data: {
                            idProduct: parseInt(productId),
                            username: productId === parseInt(idProduct) ? username : undefined,
                            hour: h,
                            date,
                            connectHistory: productId === parseInt(idProduct) ? connectHistory : null,
                            cancelId
                        }
                    });
                }
            }

        }


        const historyPayment = await prisma.historyPayment.create({
            data: {
                idProduct: parseInt(idProduct),
                username,
                date,
                paymentMethod,
                paymentStatus,
                detailDate,
                connectHistory,
                typeBreath,
                minuteBreath: minuteBreath.toString(),
                totalXp: totalXp.toString(),
                totalHp: totalHp.toString(),
                totalAttack: totalAttack.toString(),
                totalDefense: totalDefense.toString(),
                totalPrice: String(totalPrice),
                paymentProveImagePath: paymentMethod === 'qris' ? req.file.filename : undefined,
                cancelId
            },
        });

        res.status(201).json({ message: 'Order added successfully', order: historyPayment });

    } catch (error) {
        console.log('error', error)
        res.status(500).json({ error: 'Error inserting data' });
    }
});

app.get('/api/ratings/:idProduct', verifyRoles(ROLES_LIST.User), async (req, res) => {
    const { idProduct } = req.params;
    try {
        const ratings = await prisma.$queryRaw`
            SELECT r.*, u.username, u.activeAvatar
            FROM Rating r
            JOIN User u ON r.username = u.username
            WHERE r.idProduct = ${idProduct};
         `;

        let totalRating = 0;

        let ratingCount = [0, 0, 0, 0, 0];

        ratings.forEach(rating => {
            totalRating += rating.rating;
            ratingCount[rating.rating - 1]++;
        });

        const averageRating = ratings.length > 0 ? totalRating / ratings.length : 0;


        const response = {
            totalRating: ratings.length,
            averageRating,
            count: {
                5: ratingCount[4],
                4: ratingCount[3],
                3: ratingCount[2],
                2: ratingCount[1],
                1: ratingCount[0],
            },
            ratings
        };

        res.json(response);
    } catch (error) {
        console.log('error', error)
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/api/rating', verifyRoles(ROLES_LIST.User), async (req, res) => {
    try {
        const { idProduct, username, rating, description, idPayment } = req.body;

        const newRating = await prisma.rating.create({
            data: {
                idProduct: parseInt(idProduct),
                username,
                rating: parseInt(rating),
                description,
                idPayment: parseInt(idPayment),
            },
        });

        res.status(201).json({ message: 'Rating added successfully', rating: newRating });

    } catch (error) {
        console.log('error', error)
        res.status(500).json({ error: 'Error inserting data' });
    }
});

app.get('/api/rating/:username/:idPayment', verifyRoles(ROLES_LIST.User), async (req, res) => {
    try {
        const { username, idPayment } = req.params;

        const statusPayment = await prisma.historyPayment.findFirst({
            where: {
                id: parseInt(idPayment)
            }
        });

        const existingRating = await prisma.rating.findFirst({
            where: {
                username: username,
                idPayment: parseInt(idPayment)
            }
        });

        if (existingRating) {
            res.json({ statusGivenRating: true, existingRating });
        } else {
            res.json({ statusGivenRating: false, statusPayment: statusPayment.paymentStatus });
        }


    } catch (error) {
        console.log('error', error)
        res.status(500).json({ error: 'Error inserting data' });
    }
});

app.get('/api/user/ranked', verifyRoles(ROLES_LIST.User), async (req, res) => {
    try {

        const users = await prisma.user.findMany({
            orderBy: {
                healthPoint: 'desc'
            }
        });


        const rankedUsers = users.map((user, index) => {
            return {
                ...user,
                mostHealthPoint: index + 1
            };
        });

        res.json(rankedUsers);
    } catch (error) {
        console.log('error', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/api/challenge', verifyRoles(ROLES_LIST.User), async (req, res) => {
    try {
        const challange = await prisma.challenge.findMany();
        res.json(challange);
    } catch (error) {
        console.log('error', error)
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/api/dashboard', verifyRoles(ROLES_LIST.Admin), async (req, res) => {
    try {

        const today = new Date();
        today.setDate(today.getDate());
        // console.log('today', today);

        // const yesterday = new Date();
        // yesterday.setDate(today.getDate() - 2);

        // console.log('today', today.toLocaleString('en-ID', { timeZone: 'Asia/Jakarta' }))
        // console.log('yesterday', yesterday.toLocaleString('en-ID', { timeZone: 'Asia/Jakarta' }))

        const todayTimeZone = today.toLocaleString('en-ID', { timeZone: 'Asia/Jakarta' })
        // const yesterdayTimeZone = yesterday.toLocaleString('en-ID', { timeZone: 'Asia/Jakarta' })

        // const tomorrow = new Date(today);
        // tomorrow.setDate(today.getDate() - 1);

        // console.log('today', today)
        // console.log('tomorrow', tomorrow)
        const formattedDateToday = new Date(todayTimeZone).toISOString().split('T')[0];


        // console.log('formattedDateToday', formattedDateToday);

        const orderToday = await prisma.historyPayment.findMany({
            where: {
                date: formattedDateToday,
            },
        });

        const revenueToday = await prisma.$queryRaw`
            SELECT SUM(totalPrice) AS totalPriceSum
            FROM HistoryPayment
            WHERE paymentStatus = 'Lunas'
            AND date = ${formattedDateToday}
         `;

        const { totalPriceSum } = revenueToday[0];

        let formattedRevenue = 0
        if (totalPriceSum) {
            formattedRevenue = revenueToday.map(item => {
                const totalPrice = item.totalPriceSum.toLocaleString('id-ID', {
                    style: 'currency',
                    currency: 'IDR'
                });
                return totalPrice;
            });
        } else {
            formattedRevenue = ['Rp. 0']
        }


        const productCounts = await prisma.$queryRaw`
            SELECT idProduct
            FROM HistoryPayment
            WHERE paymentStatus = 'Lunas'
      `;


        const counts = productCounts.reduce((acc, curr) => {
            if ([3, 4, 5, 10, 11, 12, 13].includes(curr.idProduct)) {
                acc.lapanganBadmintonCount++;
            } else if ([2, 9].includes(curr.idProduct)) {
                acc.lapanganFutsalCount++;
            } else if ([1, 6, 7, 8, 14, 15].includes(curr.idProduct)) {
                acc.lapanganBasketCount++;
            } else if ([20, 21].includes(curr.idProduct)) {
                acc.gym++;
            } else if ([16, 17, 18, 19].includes(curr.idProduct)) {
                acc.kolamRenang++;
            }
            return acc;
        }, { lapanganBadmintonCount: 0, lapanganFutsalCount: 0, lapanganBasketCount: 0, gym: 0, kolamRenang: 0 });


        const todayWeek = new Date();

        const startOfWeek = new Date(todayWeek);
        startOfWeek.setDate(today.getDate() - today.getDay());
        const endOfWeek = new Date(todayWeek);
        endOfWeek.setDate(startOfWeek.getDate() + 6);

        // console.log('startOfWeek', startOfWeek)
        // console.log('endOfWeek', endOfWeek)


        // Format start date and end date to match the date format in your database
        const formattedStartDate = startOfWeek.toISOString().slice(0, 10);
        const formattedEndDate = endOfWeek.toISOString().slice(0, 10);

        // console.log('formattedStartDate', formattedStartDate)
        // console.log('formattedEndDate', formattedEndDate)


        const dates = [];
        let currentDate = new Date(formattedStartDate);
        const end = new Date(formattedEndDate);
        while (currentDate <= end) {
            dates.push(currentDate.toISOString().slice(0, 10));
            currentDate.setDate(currentDate.getDate() + 1);
        }

        const reservationCount = await prisma.$queryRaw`
            SELECT *
            FROM HistoryPayment
            WHERE date >= ${formattedStartDate} AND date <= ${formattedEndDate}

      `;

        // console.log('reservationCount', reservationCount)
        const countPerDate = {};
        // console.log('dates', dates)

        // Iterate over dates array
        dates.forEach(date => {
            const count = reservationCount.filter(payment => payment.date === date).length;
            countPerDate[date] = count;
        });

        const arrOfTotalPrice = {};

        // console.log('dates xx', dates)

        dates.forEach(date => {
            arrOfTotalPrice[date] = 0;
        });

        const reservationCountLunas = await prisma.$queryRaw`
        SELECT *
        FROM HistoryPayment
        WHERE date >= ${formattedStartDate} AND date <= ${formattedEndDate}
        AND paymentStatus = 'Lunas'

        `;

        reservationCountLunas.forEach(reservation => {
            const { date, totalPrice } = reservation;
            arrOfTotalPrice[date] += parseInt(totalPrice);
        });



        // console.log('dates', dates)
        // console.log('countPerDate', countPerDate)
        // console.log('arrOfTotalPrice', arrOfTotalPrice)



        const totalReservationsToday = orderToday.length
        const totalRevenue = formattedRevenue
        const totalProductsBySport = counts
        const arrOrderThisWeek = [countPerDate, dates]
        const arrRevenueThisWeek = [arrOfTotalPrice, dates]


        res.json({
            totalReservationsToday,
            totalRevenue,
            totalProductsBySport,
            arrOrderThisWeek,
            arrRevenueThisWeek
        });
    } catch (error) {
        console.log('error', error)
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/api/order', verifyRoles(ROLES_LIST.Admin), async (req, res) => {
    try {
        const order = await prisma.$queryRaw`
            SELECT p.nameDetail AS productName, hp.*
            FROM Product p
            INNER JOIN HistoryPayment hp ON p.id = hp.idProduct
            ORDER BY hp.id DESC;
        `;
        res.json(order);
    } catch (error) {
        console.log('error', error)
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/api/order/:id', verifyRoles(ROLES_LIST.Admin), async (req, res) => {

    const orderId = parseInt(req.params.id);

    try {
        const order = await prisma.$queryRaw`
            SELECT p.name AS productName, hp.*
            FROM Product p
            INNER JOIN HistoryPayment hp ON p.id = hp.idProduct
            WHERE hp.id = ${orderId}
            ORDER BY hp.id DESC;
        `;

        res.json(order);
    } catch (error) {
        console.log('error', error)
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/api/order/:id/update', verifyRoles(ROLES_LIST.Admin), async (req, res) => {
    const orderId = parseInt(req.params.id);
    const { paymentStatus } = req.body;

    try {

        const updateOrder = await prisma.historyPayment.update({
            where: { id: orderId },
            data: {
                paymentStatus,
            }
        });
        let user = []

        if (paymentStatus === 'Lunas') {
            user = await prisma.user.update({
                where: { username: updateOrder.username },
                data: {
                    healthPoint: {
                        increment: parseInt(updateOrder.totalHp),
                    },
                    experiencePoint: {
                        increment: parseInt(updateOrder.totalXp),
                    },
                    attackPoint: {
                        increment: parseInt(updateOrder.totalAttack),
                    },
                    defensePoint: {
                        increment: parseInt(updateOrder.totalDefense),
                    },
                },
            });
        } else if (paymentStatus === 'Batal') {
            user = await prisma.schedule.deleteMany({
                where: {
                    cancelId: updateOrder.cancelId,
                },
            });

        }


        res.json({ message: 'Order updated successfully', order: updateOrder, user: user });
    } catch (error) {
        console.log('error', error)
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/api/user', verifyRoles(ROLES_LIST.Admin), async (req, res) => {
    try {
        const user = await prisma.user.findMany();
        res.json(user);
    } catch (error) {
        console.log('error', error)
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/api/user/:id', verifyRoles(ROLES_LIST.Admin), async (req, res) => {
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
        console.log('error', error)
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/api/user/:id/update', verifyRoles(ROLES_LIST.Admin), async (req, res) => {
    const userId = parseInt(req.params.id);
    const { username, phoneNumber, biayaPendaftaranMembershipGym, biayaPendaftaranMembershipBadminton } = req.body;

    try {
        const updateUser = await prisma.user.update({
            where: { id: userId },
            data: {
                username: username,
                phoneNumber: phoneNumber,
                biayaPendaftaranMembershipGym: biayaPendaftaranMembershipGym === 'true' ? true : false,
                biayaPendaftaranMembershipBadminton: biayaPendaftaranMembershipBadminton === 'true' ? true : false
            }
        });

        res.json({ message: 'User updated successfully', user: updateUser });
    } catch (error) {
        console.log('error', error)
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.delete('/api/user/:id', verifyRoles(ROLES_LIST.Admin), async (req, res) => {
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
        console.log('error', error)
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

const updateStatusDailyReward = async () => {
    try {
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

const updateStatusWeeklyChallange = async () => {
    try {
        const updatedUsers = await prisma.user.updateMany({
            data: {
                statusWeeklyChallange: false
            }
        });

        console.log('User statusWeeklyChallange updated successfully.');
    } catch (error) {
        console.error('Error updating user statusWeeklyChallange:', error);
    }

};

const updateStatusMonthlyChallange = async () => {
    try {
        const updatedUsers = await prisma.user.updateMany({
            data: {
                statusMonthlyChallange: false
            }
        });

        // console.log('User statusMonthlyChallange updated successfully.');
    } catch (error) {
        console.error('Error updating user statusMonthlyChallange:', error);
    }

};

const updateStatus6MonthChallange = async () => {
    try {
        const updatedUsers = await prisma.user.updateMany({
            data: {
                status6MonthChallange: false
            }
        });

        // console.log('User status6MonthChallange updated successfully.');
    } catch (error) {
        console.error('Error updating user status6MonthChallange:', error);

    }

};

cron.schedule('*/1 * * * *', () => {
    updateStatusDailyReward();
    updateStatusWeeklyChallange();
    updateStatusMonthlyChallange();
    updateStatus6MonthChallange();
});

// cron.schedule('0 0 * * 0', async () => {
//     console.log('Running scheduled task: Sunday at midnight');

// });

// 0 */2 * * * --> every two hours
// 0 7 * * * --> every day at 7 morning

/* */

app.listen(PORT, () => {
    console.log("Express API running in port: " + PORT);
});