
////////////////////modules:
require('dotenv').config();
const axios = require('axios');
const Logger = require('./logger');


/////////////////////////////////////////connection to API:

const WHEATLEY_USERNAME = process.env.WHEATLEY_USERNAME;
const WHEATLEY_PASSWORD = process.env.WHEATLEY_PASSWORD;
const WHEATLEY_BASE_URL = 'https://wheatley.cs.up.ac.za/u23539764/api2.php';

if (!WHEATLEY_USERNAME || !WHEATLEY_PASSWORD) {
    Logger.error('Missing WHEATLEY_USERNAME or WHEATLEY_PASSWORD in .env');
    throw new Error('Missing Wheatley credentials in .env');
}

const axiosInstance = axios.create({
    baseURL: WHEATLEY_BASE_URL,
    timeout: 5000,
    headers: {
        'Content-Type': 'application/json',
        'Authorization': `Basic ${Buffer.from(`${WHEATLEY_USERNAME}:${WHEATLEY_PASSWORD}`).toString('base64')}`
    }
});


//////////////////////////////////////doing requests:

async function createRequest(type, data) {
    try {
        Logger.info(`Sending ${type} request: Method POST, URL ${WHEATLEY_BASE_URL}, Data: ${JSON.stringify({ type, ...data })}`);
        const response = await axiosInstance.post('', { type, ...data });
        Logger.info(`API request ${type}: Status ${response.status}, Response: ${JSON.stringify(response.data)}`);
        if (response.data.status !== 'success') {
            throw new Error(response.data.data || 'API request failed');
        }
        return response.data.data;
    } catch (error) {
        const errorDetails = error.response
            ? `Status ${error.response.status}, Data: ${JSON.stringify(error.response.data)}`
            : error.message;
        Logger.error(`${type} request failed: ${errorDetails}`);
        throw new Error(error.response?.data?.data || error.message);
    }
}



//////////////////////////////:Login type
async function loginUser(email, password) {
    try {
        const data = await createRequest('Login', { email, password });
        return {
            apikey: data.apikey,
            user_type: data.user_type,
            name: data.name,
            surname: data.surname
        };
    } catch (error) {
        Logger.error(`Login failed for ${email}: ${error.message}`);
        throw error; 
    }
}

//////////////////////////////:GetUserInfo type
async function validateApiKey(apiKey) {
    try {
        return await createRequest('GetUserInfo', { apikey: apiKey });
    } catch (error) {
        Logger.error(`API key validation failed: ${error.message}`);
        throw error;
    }
}

//////////////////////////////:GetAllOrders type
async function getAllOrders(apiKey) {
    try {
        return await createRequest('GetAllOrders', { apikey: apiKey });
    } catch (error) {
        Logger.error(`GetAllOrders failed: ${error.message}`);
        throw error;
    }
}



module.exports = {
    loginUser,
    validateApiKey,
    getAllOrders
};