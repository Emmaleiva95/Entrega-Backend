import express from 'express';
import { connectDB } from './db.js'
import {promises as fsp} from "fs"
import ProductRoutes from './src/routes/product.router.js'
import CartRoutes from './src/routes/cart.router.js'
import indexRoutes from './src/routes/index.router.js'
import userRoutes from './src/routes/user.router.js'
import session from 'express-session';
import cookieParser from 'cookie-parser';
// PASSPORT
import passport from 'passport';
import initializePassport from './src/config/passport.config.js';


import { Server } from 'socket.io';

import {__dirname} from './utils.js';


const app = express();

// view engine setup
app.set('views', __dirname + '/src/views');
app.set('view engine', 'ejs')


app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// COOKIES, SESSION , PASSPORT
app.use(cookieParser());

app.use(session({secret:"Mensaje secreto",
  resave:false,
  saveUninitialized:true}));
  
initializePassport();
app.use(passport.initialize())
app.use(passport.session())

//CONFIGURO LA RUTA PUBLICA, PARA ARCHIVOS PUBLICO (CSS,JS,IMG)
app.use(express.static(__dirname + '/src/public'));
app.use(ProductRoutes)
app.use(CartRoutes)
app.use(indexRoutes)
app.use(userRoutes)

// CONEXIÓN CON LA BD
connectDB();

const httpServer = app.listen(8080, () => console.log('Servidor listo en el puerto 8080'));

const socketServer = new Server (httpServer);

socketServer.on('connection', socket => {

    console.log('Un usuario se ha conectado al server socket.')
   

    socket.on('nuevoProducto', async (producto) => {
      let status = true;
  

      let id = Date.now();
      let nuevoProducto = {id, title: producto.title, description: producto.description, code:'aa-22', price:300, status, stock:16, category:'sin definir', thumbnails: producto.thumbnails}
      console.log(nuevoProducto);
      
      try {
        const data = await fsp.readFile('src/data/products.json')
        const arrayProductos = JSON.parse(data);
        arrayProductos.unshift(nuevoProducto);
        await fsp.writeFile('src/data/products.json', JSON.stringify(arrayProductos));
        
        socket.emit('createResponse', arrayProductos)

      } catch (error) {
        socket.emit('errorResponse', 'error al intentar crear el producto')
      }
        

    })

    socket.on('delete', async (id) => {
        const idProducto = id;
        try{
          const data = await fsp.readFile('src/data/products.json')
          const arrayProductos = JSON.parse(data);
          const indiceProducto = arrayProductos.findIndex((element) => { return element.id == idProducto});
          if(indiceProducto >= 0){
            arrayProductos.splice(indiceProducto,1);
            await fsp.writeFile('src/data/products.json', JSON.stringify(arrayProductos));
            socket.emit('deleteResponse',arrayProductos);
          }else{
            socket.emit('errorResponse', 'producto no encontrado')
          }
      
         
        }catch(error){
            console.log(error);
        }
    })
} )
