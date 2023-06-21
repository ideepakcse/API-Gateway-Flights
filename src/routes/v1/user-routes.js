const express = require('express');
const { UserController } = require('../../controllers');
const { AuthRequestMiddlewares } = require('../../middlewares');

const router = express.Router();

router.post('/signup',AuthRequestMiddlewares.validateAuthRequest, UserController.signup);
router.post('/signin',AuthRequestMiddlewares.validateAuthRequest, UserController.signin);

//Body->>    role-admin,flight_company
//           id-userid
//header ->> x-access-token:jtw key
router.post('/role',AuthRequestMiddlewares.checkAuth, AuthRequestMiddlewares.isAdmin, UserController.addRoleToUser);

module.exports = router;