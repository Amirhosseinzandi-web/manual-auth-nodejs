import dotenv from "dotenv";
import userConnection from "./server/db/db.js";
import express from "express";
import userModel from "./server/models/users-model.js";
import _ from "lodash";
dotenv.config();


const app = express();
app.use(express.json());

const allowedRoutes = ["/user/register", "/user/login", "/user/logout"]


const authMiddleware = async (req, res, next) => {

    if (allowedRoutes.includes(req.path)) {
        return next();
    }

    try {
        const token = req.header('X-Authorization');
        if (!token) {
            return res.status(401).send('Access denied. No token provided , first try to login');
            // res.redirect('/login');
        }
        const currentUser = await userModel.findByToken(token);
        if (!currentUser) {
            return res.status(404).send('user not found');
        }

        req.user = currentUser;
        req.token = token;
        next();

    }
    catch (err) {
        console.log("error in auth middleware", err);

    }
}


app.use(authMiddleware);



const Main = () => {

    userConnection();
}

Main();


// ************************Routes****************************


app.get("/user", async (req, res) => {
    const allData = await userModel.find();
    res.send(allData)
})





app.post("/user/register", async (req, res) => {
    const customBody = _.pick(req.body, ["email", "password"]);
    const isUserExist = await userModel.findOne({ email: customBody.email });
    if (isUserExist) {
        return res.status(400).send("user already exist");
    }
    const currentUser = await userModel.create(customBody);
    const token = await currentUser.generateAuthToken();
    res.header("X-Authorization", token);
    res.send(currentUser)
})





app.get("/user/login", async (req, res) => {
    try {

        const customBody = _.pick(req.body, ["email", "password"]);
        const currentUserByEmail = await userModel.authEmail(customBody.email);
        if (!currentUserByEmail) {
            return res.status(400).send("user not found");
        }
        const currentUserByPassword = await userModel.authPassword(customBody.email, customBody.password);
        if (!currentUserByPassword) {
            res.status(400).send("wrong password");
        }
        const token = await currentUserByEmail.generateAuthToken();
        res.header("X-Authorization", token);
        res.send(currentUserByEmail)

    }
    catch (err) {
        console.log("/user/login", err);
    }
})



app.delete("/user/logout", async (req, res) => {
    try {
        const token = req.header('X-Authorization');
        if (!token) {
            return res.status(401).send("Access denied. No token provided.");
        }
        await userModel.logout(token);
        res.status(200).send("logged out successfully");
    }
    catch (err) {
        console.log("/user/logout", err);
        res.status(500).send("logout failed");
    }
})



app.listen(3000, () => {
    console.log("server is running on port 3000");
})