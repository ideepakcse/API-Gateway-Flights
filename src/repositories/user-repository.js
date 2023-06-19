const CrudRepository = require('./crud-repository');

const { User } = require('../models');

class UserRepository extends CrudRepository {
    constructor() {
        super(User);
    }

    async getUserById(userId) {
        const user = await User.findByPk(userId, {
                attributes: ['email', 'id']
        });
        if(!user) {
            throw new AppError('Not able to find the user', StatusCodes.NOT_FOUND);
        }
        return user;
       
    }

    async getUserByEmail(userEmail) {
        const user = await User.findOne({ 
            where: { email: userEmail} 
        });
        if(!user) {
            throw new AppError('Not able to find the user', StatusCodes.NOT_FOUND);
        }
        return user;
    }
}

module.exports = UserRepository;