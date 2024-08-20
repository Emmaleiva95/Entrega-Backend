import mongoose from "mongoose";

const usersSchema = new mongoose.Schema({
    first_name: {
        type: String,
        required: true,
         trim:true
    },
    last_name: {
        type: String,
        required: true,
        trim:true
    },
    email: {
        type: String,
        required: true,
        unique:true,
        trim:true
    },
    age: {
        type: Number,
        required: true
    },
    password: {
        type: String,
        required: true,
        trim:true
    },
    cart: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "cart",
    },
    role: {
        type: String,
        required: true,
        trim:true
    }
    
})


export default mongoose.model('Users', usersSchema);