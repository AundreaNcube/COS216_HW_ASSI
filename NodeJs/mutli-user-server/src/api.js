
//////////////////////////////////:modules:
require('dotenv').config();
const axios = require('axios');
const Logger = require('./logger');



/////////////////////////////////////////connection to API:
const WHEATLEY_USERNAME = process.env.WHEATLEY_USERNAME;
const WHEATLEY_PASSWORD = process.env.WHEATLEY_PASSWORD;
const WHEATLEY_BASE_URL = 'https://wheatley.cs.up.ac.za/u23539764/api2.php';

if (!WHEATLEY_USERNAME || !WHEATLEY_PASSWORD) {
    Logger.error(`Missing Wheatley credentials in .env: WHEATLEY_USERNAME=${WHEATLEY_USERNAME}, WHEATLEY_PASSWORD=${WHEATLEY_PASSWORD}`);
    throw new Error('Missing Wheatley credentials in .env');
}




////////////:axios
const axiosInstance = axios.create({
    baseURL: WHEATLEY_BASE_URL,
    timeout: 10000, // Increased from 5000ms for reliability
    headers: {
        'Content-Type': 'application/json',
        'Authorization': `Basic ${Buffer.from(`${WHEATLEY_USERNAME}:${WHEATLEY_PASSWORD}`).toString('base64')}`
    }
});



///////////////////////request function::

async function createRequest(type, data) {
    const requestBody = { type, ...data };
    try {
    
        Logger.info(`API Request ${JSON.stringify(requestBody)}`);
        const response = await axiosInstance.post('', requestBody);
        Logger.info(`API Response ${JSON.stringify({
            status: response.status,
            data: response.data
        })}`);

        if (response.data.status !== 'success') {
            throw new Error(response.data.data || response.data.error || 'API request failed');
        }
        return response.data.data;
    } catch (error) {
        const errorDetails = {
            type,
            error: error.message,
            response: error.response ? {
                status: error.response.status,
                data: error.response.data
            } : null,
            request: requestBody
        };
        Logger.error(`API Error ${JSON.stringify(errorDetails)}`);
        throw new Error(error.response?.data?.data || error.response?.data?.error || error.message);
    }
}



/////////////////////////////:::login

async function loginUser(email, password) {
    try {
        const data = await createRequest('Login', { email, password });
        const result = {
            apikey: data.apikey || data.api_key,
            user_type: data.user_type || data.type,
            name: data.name,
            surname: data.surname
        };
        Logger.info(`User login successful: ${JSON.stringify(result)}`);
        return result;
    } catch (error) {
        throw error;
    }
}



/////////////////::validate
async function validateApiKey(apiKey) {
    try {
        const userInfo = await createRequest('GetUserInfo', { apikey: apiKey });
        Logger.info(`API key validation successful: ${JSON.stringify(userInfo)}`);
        return {
            id: userInfo.id,
            user_type: userInfo.user_type || userInfo.type,
            name: userInfo.name,
            surname: userInfo.surname,
            email: userInfo.email
        };
    } catch (error) {
        throw error;
    }
}





//////////////////////////:get all orders
async function getAllOrders(apiKey) {
    try {
        const orders = await createRequest('GetAllOrders', { apikey: apiKey });
        Logger.info(`Successfully fetched ${orders.length} orders`);
        return orders;
    } catch (error) {
        throw error;
    }
}



/////////////////: create a new order
async function createOrder(apiKey, destination_latitude, destination_longitude, products) {
    try {
        const order = await createRequest('CreateOrder', {
            apikey: apiKey,
            destination_latitude,
            destination_longitude,
            products
        });
        Logger.info(`Order created successfully: ${JSON.stringify(order)}`);
        return order;
    } catch (error) {
        throw error;
    }
}




///////////////////////:update order's state
async function updateOrder(apiKey, order_id, state) {
    try {
        const result = await createRequest('UpdateOrder', {
            apikey: apiKey,
            order_id,
            state
        });
        Logger.info(`Order ${order_id} updated successfully: ${JSON.stringify(result)}`);
        return result;
    } catch (error) {
        throw error;
    }
}




//////////////////////: create a new drone
async function createDrone(apiKey, options = {}) {
    try {
        const data = { apikey: apiKey };
        if (options.latest_latitude !== undefined) data.latest_latitude = options.latest_latitude;
        if (options.latest_longitude !== undefined) data.latest_longitude = options.latest_longitude;
        if (options.altitude !== undefined) data.altitude = options.altitude;
        if (options.battery_level !== undefined) data.battery_level = options.battery_level;
        if (options.current_operator_id !== undefined) data.current_operator_id = options.current_operator_id;

        const drone = await createRequest('CreateDrone', data);
        Logger.info(`Drone created successfully: ${JSON.stringify(drone)}`);
        return drone;
    } catch (error) {
        throw error;
    }
}




//////////////////////: get all drones
async function getAllDrones(apiKey) {
    try {
        const drones = await createRequest('GetAllDrones', { apikey: apiKey });
        Logger.info(`Successfully fetched ${drones.length} drones`);
        return drones;
    } catch (error) {
        throw error;
    }
}





////////////////////////// update drone's status
async function updateDrone(apiKey, id, options = {}) {
    try {
        const data = { apikey: apiKey, id };
        if (options.current_operator_id !== undefined) data.current_operator_id = options.current_operator_id;
        if (options.is_available !== undefined) data.is_available = options.is_available;
        if (options.latest_latitude !== undefined) data.latest_latitude = options.latest_latitude;
        if (options.latest_longitude !== undefined) data.latest_longitude = options.latest_longitude;
        if (options.altitude !== undefined) data.altitude = options.altitude;
        if (options.battery_level !== undefined) data.battery_level = options.battery_level;

        const result = await createRequest('UpdateDrone', data);
        Logger.info(`Drone ${id} updated successfully: ${JSON.stringify(result)}`);
        return result;
    } catch (error) {
        throw error;
    }
}



///////////////////////////:get order details
async function getOrderDetails(apiKey, customer_id) {
    try {
        const userInfo = await createRequest('GetUserById', { apikey: apiKey, user_id: customer_id });
        const result = {
            name: userInfo.name,
            surname: userInfo.surname
        };
        Logger.info(`Retrieved order details for customer ${customer_id}: ${JSON.stringify(result)}`);
        return result;
    } catch (error) {
        Logger.error(`getOrderDetails failed: ${error.message}`);
        throw error;
    }
}







///////////////////////////:export functions
module.exports = {
    loginUser,
    validateApiKey,
    getAllOrders,
    createOrder,
    updateOrder,
    getAllDrones,
    updateDrone,
    createDrone,
    getOrderDetails
};
