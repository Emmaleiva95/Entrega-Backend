import mongoose from "mongoose";

export const connectDB = async () => {
    try {
        await mongoose.connect('mongodb+srv://manutesting:manu1234@clustertestingdb.yqbmfuc.mongodb.net/?retryWrites=true&w=majority&appName=ClusterTestingDB');
        console.log('DB CONNECTED')
    } catch (error) {
        console.log(error)
    }
}