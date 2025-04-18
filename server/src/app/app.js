require("dotenv").config();
const express = require('express');
const app = express();
const cors = require('cors');
const bodyParser = require('body-parser');
const morgan = require('morgan');
const compression = require('compression');
const { default: helmet } = require('helmet');
const cookieParser = require('cookie-parser');
const router = require('../routes/mainRoute');
const { mysqlConnect } = require('../databases/mysql/mysqlConnect');
const errorHandler = require('../middlewares/errorHandler');

// test

// config
require('express-async-handler')

// init middlewares
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(morgan('dev'));
app.use(compression());
app.use(helmet());
app.use(cookieParser());

// init databases
mysqlConnect();

// init routes
app.use('/',router);

// init error handler
app.use(errorHandler);


module.exports = app;