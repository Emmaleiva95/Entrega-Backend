import mongoose from "mongoose";


const cartSchema = new mongoose.Schema({

    products: [
        {
            product: {
                type: mongoose.Schema.Types.ObjectId,
                ref: "Products",
                required: true,
                minLength: 1
            }
            ,
            quantity: {
                type: Number,
                required: true
            }
        }

    ]

})

export default mongoose.model('Cart', cartSchema);