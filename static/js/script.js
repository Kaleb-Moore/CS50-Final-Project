var modalWrap = null;
const showModal = () => {

    if(modalWrap !== null){
        modalWrap.remove();
    }
    modalWrap = document.createElement('div');
    modalWrap.innerHTML = `
    <div class="modal fade" id="update-modal" tabindex="-1" aria-labelledby="modal-title" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title text-center" id="modal-title">Edit Product</h5>
                    <button class="btn-close" id="update-close" type="button" data-bs-dismiss="modal" aria-label="close"></button>
                </div>
                <form action="/update" method="POST" >
                    <div class="modal-body">
                        <label for="Part" class="form-label">Part Name</label>
                        <input id="update-part" class="form-control" maxlength="20" minlength="2" name="update-part" required="" type="text" value="" readonly>
                        <label for="Quantity" class="form-label">Quantity</label>
                        <input id="update-quantity" class="form-control" name="update-quantity" required="" min="0" max="" type="number" value="">
                        <label for="Price" class="form-label">Price</label>
                        <input id="update-price" class="form-control" name="update-price" required="" type="number" value="">
                    </div>
                    <div class="f-container mb-3">
                        <button type="submit" class="btn btn-primary ms-3 me-3">Update</button>
                        <button type="submit" formaction="/delete" class="btn btn-primary ms-3 me-3">Delete</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    `;

    document.body.append(modalWrap);
    var modal =  new bootstrap.Modal(modalWrap.querySelector('.modal'));
    modal.show();
}

document.querySelectorAll('.card-header').forEach(item => {
    item.addEventListener('click', e => {
        showModal();
        qty = e.target.parentNode.children[1].children[0].children[0].children[1].innerHTML;
        price = e.target.parentNode.children[1].children[0].children[2].children[1].innerHTML.substring(1);
        document.getElementById('update-part').setAttribute('value', e.target.innerHTML);
        document.getElementById('update-quantity').setAttribute('value', qty);
        document.getElementById('update-price').setAttribute('value', price);

    })
  })

const search = () => {
    searchInput = document.getElementById('searchbar').value;
    gallery = document.getElementById('gallery');

    for(let i = 0; i < gallery.children.length; i++) {
        let product = gallery.children[i].children[0].children[0].innerHTML.toLowerCase();
        if(product.includes(searchInput)) {
          gallery.children[i].setAttribute('style', 'display: block')
        } else if(!(product.includes(searchInput))) {
          gallery.children[i].setAttribute('style', 'display: none')
        }
    }
}

document.getElementById('searchbar').addEventListener('keyup', () => {
    search();
})