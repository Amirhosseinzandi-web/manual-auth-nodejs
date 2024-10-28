import mongoose from "mongoose";
import validator from "validator"
import jwt from "jsonwebtoken"
import bcrypt from "bcryptjs"
import _ from "lodash"



const userSchema = new mongoose.Schema({

    email: {
        type: String,
        required: true,
        trim: true,
        lowercase: true,
        minlength: 3,
        validator: {
            validator: validator.isEmail,
            message: `{VALUE} is not a valid email`
        }
    },
    password: {
        type: String,
        required: true,
        trim: true,
        minlength: 8
    },
    register_date: {
        type: Date,
        default: Date.now()
    },
    auth: {
        access: String,
        token: String

    }


})


userSchema.methods.toJSON = function () {
    const userObject = this.toObject();

    return _.pick(userObject, ["_id", "email", "password", "register_date", "auth"]);
};



userSchema.statics.findByToken = async function (token) {
    const decoded = jwt.verify(token, process.env.JWT_KEY);
    const foundUser = await this.findById(decoded._id);
    return foundUser
}



userSchema.pre("validate", async function (next) {
    if (this.isNew || this.isModified("password")) {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
    }
    next();
})



userSchema.methods.generateAuthToken = async function () {
    const access = "auth";
    const token = jwt.sign({ _id: this._id, access: access }, process.env.JWT_KEY);

    this.auth = { access, token };
    await this.save();
    return token
}




userSchema.statics.authEmail = async function (email) {
    const user = await userModel.findOne({ email });
    return user;
};



userSchema.statics.authPassword = async function (email, password) {
    const user = await userModel.findOne({ email });
    const isPasswordMatch = await bcrypt.compare(password, user.password);

    if (isPasswordMatch) {
        return true;
    } else {
        return false;
    }
}



userSchema.statics.logout = async function (token) {
    const foundUser = await this.findByToken(token);

    if (!foundUser) {
        throw new Error("user not found")
    }
    foundUser.auth = null
    await foundUser.save()
    return foundUser
}



const userModel = mongoose.model("userModel", userSchema, "users");


export default userModel