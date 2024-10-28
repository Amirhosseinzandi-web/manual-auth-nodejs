import mongoose from "mongoose";



const userConnection = async () => {
    try {

        const url = "mongodb://127.0.0.1:27017/user";
        await mongoose.connect(url);
        console.log("Database connected");

    }
    catch (err) {
        console.log("error with connection");

    }
}


export default userConnection