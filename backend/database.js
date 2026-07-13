// Conexión a MySQL (Aiven) con Sequelize
import { Sequelize } from 'sequelize'
import dotenv from 'dotenv'
import { fileURLToPath } from 'url'
import { dirname, join } from 'path'

const __dirname = dirname(fileURLToPath(import.meta.url))
dotenv.config({ path: join(__dirname, '.env') })

export const sequelize = new Sequelize(
  process.env.DB_NAME,
  process.env.DB_USER,
  process.env.DB_PASSWORD,
  {
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT) || 3306,
    dialect: 'mysql',
    logging: false,
    // Aiven exige SSL. Si algún día usás una base local sin SSL, poné DB_SSL=false en el .env
    dialectOptions: process.env.DB_SSL === 'false' ? {} : { ssl: { rejectUnauthorized: false } },
    // Pool ampliado para el día del evento: 5 escáneres en puerta + admin + webhooks en simultáneo.
    pool: { max: 10, min: 0, idle: 10000, acquire: 30000 },
  }
)
