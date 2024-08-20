import mongoose from "mongoose";
import mongoosePaginate from "mongoose-paginate-v2";

const productsSchema = new mongoose.Schema({
    title: {
        type: String,
        required: true,
         trim:true
    },
    description: {
        type: String,
        required: true,
        trim:true
    },
    code: {
        type: String,
        required: true,
        trim:true
    },
    price: {
        type: Number,
        required: true
    },
    status: {
        type: Boolean,
        required: true
    },
    stock: {
        type: Number,
        required: true
    },
    category: {
        type: String,
        required: true,
        trim:true
    },
    thumbnails: [{
        type: String
    }]
    
})

productsSchema.plugin(mongoosePaginate);
export default mongoose.model('Products', productsSchema);