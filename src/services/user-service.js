const { StatusCodes } = require('http-status-codes');
const { UserRepository } = require('../repositories');
const AppError = require('../utils/errors/app-error');

const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const {ServerConfig}=require('../config');

const userRepository = new UserRepository();

async function create(data) {
    try {
        console.log("inside service");
        const user = await userRepository.create(data);
        return user;
    } catch(error) {
        if(error.name == 'SequelizeValidationError' || error.name == 'SequelizeUniqueConstraintError') {
            let explanation = [];
            error.errors.forEach((err) => {
                explanation.push(err.message);
            });
            throw new AppError(explanation, StatusCodes.BAD_REQUEST);
        }
        throw new AppError('Cannot create a new user object', StatusCodes.INTERNAL_SERVER_ERROR);
    }
}

async function signIn(email, plainPassword) {
    try {
        // step 1-> fetch the user using the email
        const user = await userRepository.getUserByEmail(email);
        console.log(user);
        // step 2-> compare incoming plain password with stores encrypted password
        const passwordsMatch = checkPassword(plainPassword, user.password);
        if(!passwordsMatch) {
            throw new AppError('Invalid password', StatusCodes.BAD_REQUEST);
        }
        // step 3-> if passwords match then create a token and send it to the user
        const newJWT = createToken({email: user.email, id: user.id});
        return newJWT;
    } catch (error) {
        if(error instanceof AppError) throw error;
        throw new AppError('Something went wrong', StatusCodes.INTERNAL_SERVER_ERROR);
    }
}

async function isAuthenticated(token) {
    try {
        const response = verifyToken(token);
        if(!response) {
            throw new AppError('Invalid JWT token', StatusCodes.BAD_REQUEST);
        }
        const user = await userRepository.getUserById(response.id);
        if(!user) {
            throw new AppError('No user found', StatusCodes.NOT_FOUND);
        }
        return user.id;
    } catch(error) {
        if(error instanceof AppError) throw error;
        if(error.name == 'JsonWebTokenError') {
            throw new AppError('Invalid JWT token', StatusCodes.BAD_REQUEST);
        }
        if(error.name == 'TokenExpiredError') {
            throw new AppError('JWT token expired', StatusCodes.BAD_REQUEST);
        }
        throw new AppError('Something went wrong', StatusCodes.INTERNAL_SERVER_ERROR);
    }
}
function createToken(user) {
        try {
            const result = jwt.sign(user, ServerConfig.JWT_KEY, {expiresIn: ServerConfig.JWT_EXPIRY});
            return result;
        } catch (error) {
            throw error;
        }
    }

function verifyToken(token) {
        try {
            const response = jwt.verify(token, ServerConfig.JWT_KEY);
            return response;
        } catch (error) {
            throw error;
        }
    }

function checkPassword(userInputPlainPassword, encryptedPassword) {
        try {
            return bcrypt.compareSync(userInputPlainPassword, encryptedPassword);
        } catch (error) {
            throw error;
        }
    }

module.exports = {
    create,
    signIn,
    isAuthenticated
}