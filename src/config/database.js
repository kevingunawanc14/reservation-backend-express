import { Sequelize } from "sequilize";

const db = new Sequelize('coba', 'root', '', {
    host: 'localhost',
    dialect: 'mysql'
});

export default db;