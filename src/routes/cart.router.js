import { Router } from "express";
import { promises as fsp } from "fs"
import cartModel from "../models/cart.model.js";
import productsModel from "../models/products.model.js";


const router = Router();
/* 
    ID DEL CARRITO ESTÁTICO : 6691317f727c2ab92728c2ec.
*/


// OBTENER PRODUCTOS DEL CARRITO.
router.get('/api/carts/:cid', async (req, res) => {
    const idCarrito = req.params.cid;
    try {
        const cart = await cartModel.findById(idCarrito).populate({
            path: 'products.product',
            model: productsModel
        });
        console.log(JSON.stringify(cart, null, 4));
        res.render('cart', { products: cart.products });
    } catch (error) {
        console.log(error);
    }

});




// PETICIÓN POST - CREAR CARRITO - ANTIGUA FORMA.
router.post('/api/carts/', async (req, res) => {
    const { products } = req.body;
    try {
        if (products == undefined || products == '' || products.length == 0) {
            res.send('No puede crear un carrito sin productos.');
        } else {
            let idCart = `c-${Date.now()}`;
            let nuevoCarrito = { idCart, products };
            const data = await fsp.readFile('src/data/cart.json')
            const listadoCarritos = JSON.parse(data);
            listadoCarritos.push(nuevoCarrito);
            await fsp.writeFile('src/data/cart.json', JSON.stringify(listadoCarritos));

            res.send(nuevoCarrito);
        }

    } catch (error) {
        console.log(error);
    }

});

// PETICIÓN PUT - MODIFICAR CARRITO COMPLETO
router.put('/api/carts/:cid', async (req, res) => {
    const { products } = req.body;
    const idCarrito = req.params.cid;
    try {
        if (products == undefined || products == '' || products.length == 0) {
            res.send('No puede modificar un carrito sin productos.');
        } else {

            const carritoModificado = await cartModel.findByIdAndUpdate(idCarrito, products, { new: true });
            if (!carritoModificado) return res.status(404).send("No se ha encontrado el curso solicitado.")

            res.send(carritoModificado);
        }

    } catch (error) {
        console.log(error);
    }

});


router.delete('/api/carts/:cid/product/:pid', async (req, res) => {
    const idProducto = req.params.pid;
    const idCarrito = req.params.cid;
    try {
        /* VALIDAR QUE EXISTA EL CARRITO */
        const carritoEncontrado = await cartModel.findById(idCarrito);
        if (!carritoEncontrado) return res.send("No se ha encontrado el curso solicitado.");

        /* ELIMINAR EL PRODUCTO DEL CARRITO */
        const indexProduct = carritoEncontrado.products.findIndex((element) => { return element.product == idProducto });
        if (indexProduct >= 0) {
            carritoEncontrado.products.splice(indexProduct, 1);
            await carritoEncontrado.save();

            res.send('producto eliminado')
        } else {
            res.send('ese producto no se encuentra dentro del carrito');
        }


    } catch (error) {
        console.log(error);
    }

});


router.delete('/api/carts/:cid', async (req, res) => {

    const idCarrito = req.params.cid;
    try {
        /* VALIDAR QUE EXISTA EL CARRITO */
        const carritoEncontrado = await cartModel.findById(idCarrito);
        if (!carritoEncontrado) return res.send("No se ha encontrado el curso solicitado.");

        carritoEncontrado.products = [];
        await carritoEncontrado.save();
        res.send('carrito vacío');
    } catch (error) {
        console.log(error);
    }

});



router.put('/api/carts/:cid/product/:pid', async (req, res) => {
    const idProducto = req.params.pid;
    const idCarrito = req.params.cid;
    const quantity = req.body.quantity;
    try {
        if (quantity == undefined || quantity <= 0) {
            res.send('La cantidad debe ser mayor a 0.');
        } else {

            /* VALIDAR QUE EXISTA EL CARRITO */
            const carritoEncontrado = await cartModel.findById(idCarrito);
            if (!carritoEncontrado) return res.send("No se ha encontrado el curso solicitado.");

            /* ELIMINAR EL PRODUCTO DEL CARRITO */
            const indexProduct = carritoEncontrado.products.findIndex((element) => { return element.product == idProducto });
            if (indexProduct >= 0) {
                carritoEncontrado.products[indexProduct].quantity = quantity;
                await carritoEncontrado.save();
                res.send('producto actualizado')
            } else {
                res.send('ese producto no se encuentra dentro del carrito');
            }
        }



    } catch (error) {
        console.log(error);
    }

});

// PETICIÓN POST - AGREGAR PRODUCTO AL CARRITO
router.post('/api/carts/:cid/product/:pid', async (req, res) => {
    const quantity = parseInt(req.body.quantity);
    const idCarrito = req.params.cid;
    const idProducto = req.params.pid;
    try {
        if (quantity == undefined || quantity <= 0) {
            res.send('La cantidad debe ser mayor a 0.');
        } else {

            /* VALIDAR QUE EXISTA EL CARRITO */
            const carritoEncontrado = await cartModel.findById(idCarrito);
            if (!carritoEncontrado) return res.send("No se ha encontrado el curso solicitado.");

            /* VALIDAR QUE EXISTA EL PRODUCTO */
            const productoEncontrado = await productsModel.findById(idProducto);
            if (!productoEncontrado) return res.send("No se ha encontrado el producto solicitado.");

            /* VALIDAR QUE EL PRODUCTO ESTE O NO EN EL CARRITO */
            const productoEnElCarrito = carritoEncontrado.products.findIndex((element) => { return element.product == idProducto })
            console.log('indice en el carrito: ', productoEnElCarrito)
            // VERIFICAR SI EL PRODUCTO YA SE ENCUENTRA EN EL CARRITO
            if (productoEnElCarrito >= 0) {
                carritoEncontrado.products[productoEnElCarrito].quantity += quantity;
                await carritoEncontrado.save();
            } else {
                carritoEncontrado.products.push({ product: idProducto, quantity });
                await carritoEncontrado.save();
            }

            res.redirect('/api/products?msg=1')
        }

    } catch (error) {
        console.log(error);
    }


});

export default router;