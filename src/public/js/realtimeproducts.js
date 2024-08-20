// RENDERIZAR LOS PRODUCTOS EN TIEMPO REAL.
function renderProducts(products) {

    const containerProductos = document.getElementById('containerProductos');
    containerProductos.innerHTML = '';
    for (const product of products) {
        containerProductos.innerHTML += `
                    <div class="col-md-4 my-3">
                        <div class="card">
                            <img src="assets/img/${product.thumbnails[0]}" class="card-img-top"
                                alt="Product 1">
                            <div class="card-body">
                                <h5 class="card-title">
                                    ${product.title}
                                </h5>
                                <p class="card-text">
                                     ${product.description}
                                </p>
                                <a href="#" class="btn btn-danger btn-eliminar" id=" ${product.id}">Eliminar</a>
                            </div>
                        </div>
                    </div>
        `;
    }

    const listadoBotones = document.querySelectorAll('.btn-eliminar')

    listadoBotones.forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            socket.emit('delete', btn.id);
        })

    });
}

// INSTANCIAMOS EL SOCKET DESDE EL CLIENTE
const socket = io();

// ESCUCHAMOS LAS RESPUSTAS DEL SERVER

socket.on('deleteResponse', data => {
    renderProducts(data)
    alert('Producto eliminado correctamente');
})

socket.on('createResponse', data => {

    renderProducts(data)
    alert('Producto creado correctamente');
})


// PROGRAMAMOS LOS BOTONES PARA ELIMINAR PRODUCTOS
const listadoBotones = document.querySelectorAll('.btn-eliminar')

listadoBotones.forEach(btn => {

    btn.addEventListener('click', (e) => {
        e.preventDefault();
        socket.emit('delete', btn.id);
    })

});

/* PROGRAMAMOS FORMULARIO DE AGREGAR PRODUCTO */

const formAgregar = document.getElementById('formAgregar');

formAgregar.addEventListener('submit', (e) => {
    e.preventDefault();
    console.log('envio')
    const title = document.getElementById('inputTitulo').value;
    const description = document.getElementById('inputDescripcion').value;
    const imagen = document.getElementById('inputImagen').value;

    if (title === '' || description === '' || imagen === '') {
        alert('Todos los campos son obligatorios');
        return;
    }

    const producto = {
        title,
        description,
        thumbnails: [imagen]
    }

    socket.emit('nuevoProducto', producto);

    formAgregar.reset();
})