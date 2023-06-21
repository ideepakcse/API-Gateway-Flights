const CrudRepository = require('./crud-repository');
const { Role } = require('../models');


class RoleRepository extends CrudRepository {
    constructor() {
        super(Role);
    }

    async getRoleByName(name) {
        const role = await Role.findOne({ where: { name: name } });
        if(!role) {
            throw new AppError('Not able to find the role', StatusCodes.NOT_FOUND);
        }
        return role;
    }
}

module.exports = RoleRepository;