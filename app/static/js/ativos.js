document.addEventListener("DOMContentLoaded", () => {

    const botoesEditar = document.querySelectorAll(".btn-editar");

    const form = document.getElementById("formEditar");

    botoesEditar.forEach(botao => {

        botao.addEventListener("click", () => {

            const id = botao.dataset.id;

            form.action = `/ativos/editar/${id}`;

            document.getElementById("editarNome").value =
                botao.dataset.nome;
                
            document.getElementById("editarProduto").value =
                botao.dataset.produto;

            document.getElementById("editarVersao").value =
                botao.dataset.versao;

        });

    });

});