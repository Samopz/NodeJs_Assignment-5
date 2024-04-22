const mongoose = require('mongoose');
const joi = require('joi');


const userSchema = joi.object({
    name: joi.string().required(),
    email: joi.string().email().required(),
    password: joi.string().required(),
    confirmPassword: joi.ref('password')
});

const loginSchema = joi.object({
    email: joi.string().email().required(),
    password: joi.string().required()
});

const postSchema = Joi.object({
    title: Joi.string().required(),
    body: Joi.string().required()
});

const patchPostSchema = Joi.object({
    title: Joi.string().optional(),
    body: Joi.string().optional()
}).min(1);

const getPostsSchema = Joi.object({
    limit: Joi.number().integer().min(1).optional(),
    page: Joi.number().integer().min(1).optional(),
    order: Joi.string().valid('asc', 'desc').optional(),
    orderBy: Joi.string().valid('createdAt', 'updatedAt').optional()
});

// Model
const User = mongoose.model('User',
    userSchema,
    loginSchema,
    postSchema,
    patchPostSchema,
    getPostsSchema
);
export default User;