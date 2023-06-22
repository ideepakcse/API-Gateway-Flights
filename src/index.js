const express=require('express');
const rateLimit = require('express-rate-limit');
const { createProxyMiddleware } = require('http-proxy-middleware');

const {ServerConfig}=require('./config');

const apiRoutes=require('./routes');


const app = express();


const limiter = rateLimit({
	windowMs: 15 * 60 * 1000, // 2 minutes
	max: 100, // Limit each IP to 2 requests per `window` (here, per 15 minutes)
});

app.use(express.json());
app.use(express.urlencoded({extended:true}));
app.use(limiter);

app.use('/api',apiRoutes);

//app.use('/api', createProxyMiddleware({ target: 'http://www.example.org', changeOrigin: true }));
app.use('/flightsService', createProxyMiddleware({ target: ServerConfig.FLIGHT_SERVICE, changeOrigin: true, }));
app.use('/bookingService', createProxyMiddleware({ target: ServerConfig.BOOKING_SERVICE, changeOrigin: true, }));

app.listen(ServerConfig.PORT, () => {
    console.log(`Successfully started the server on PORT : ${ServerConfig.PORT}`);
});

/**
 * user
 *  |
 *  v
 * from : localhost:3001 (API Gateway)  to---> localhost:4000/api/v1/bookings
 * 
 *                                      to---> localhost:3000/api/v1/flights
 */
